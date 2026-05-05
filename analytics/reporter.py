"""Generate JSON/PDF intelligence exports."""

from __future__ import annotations

import io
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from loguru import logger
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from pipeline.models import (
    Alert,
    AuthAttempt,
    HoneypotSession,
    HttpRequest,
    Payload,
    ReportType,
    ThreatReport,
)

REPORTS_ROOT = Path(os.getenv("REPORTS_DIR", "./reports"))

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Image as RLImage
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
except Exception:  # pragma: no cover
    colors = None
    LETTER = None
    inch = None
    RLImage = None

try:
    import matplotlib

    matplotlib.use("Agg")  # type: ignore
    import matplotlib.pyplot as plt
except Exception:  # pragma: no cover
    plt = None


def _window(period_days: int) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=period_days)
    return start, now


async def _collect_stats(session: AsyncSession, period_days: int) -> dict[str, Any]:
    start, end = _window(period_days)
    total_sessions = await session.scalar(
        select(func.count()).select_from(HoneypotSession).where(HoneypotSession.started_at >= start)
    )
    unique_ips = await session.scalar(
        select(func.count(distinct(HoneypotSession.src_ip)))
        .select_from(HoneypotSession)
        .where(HoneypotSession.started_at >= start)
    )
    payloads = (
        (
            await session.execute(
                select(Payload.payload_type, func.count().label("c"))
                .join(HoneypotSession, Payload.session_id == HoneypotSession.id)
                .where(HoneypotSession.started_at >= start)
                .group_by(Payload.payload_type)
                .order_by(func.count().desc())
                .limit(8)
            )
        )
        .all()
    )
    top_ips = (
        (
            await session.execute(
                select(HoneypotSession.src_ip, func.count().label("c"))
                .where(HoneypotSession.started_at >= start)
                .group_by(HoneypotSession.src_ip)
                .order_by(func.count().desc())
                .limit(10)
            )
        )
        .all()
    )
    combos = (
        (
            await session.execute(
                select(AuthAttempt.username, AuthAttempt.password, func.count().label("c"))
                .join(HoneypotSession, AuthAttempt.session_id == HoneypotSession.id)
                .where(HoneypotSession.started_at >= start)
                .group_by(AuthAttempt.username, AuthAttempt.password)
                .order_by(func.count().desc())
                .limit(10)
            )
        )
        .all()
    )
    http_targets = (
        (
            await session.execute(
                select(HttpRequest.path, func.count().label("c"))
                .join(HoneypotSession, HttpRequest.session_id == HoneypotSession.id)
                .where(HoneypotSession.started_at >= start)
                .group_by(HttpRequest.path)
                .order_by(func.count().desc())
                .limit(8)
            )
        )
        .all()
    )
    alerts = await session.scalar(
        select(func.count()).select_from(Alert).where(Alert.triggered_at >= start)
    )
    return {
        "period_start": start.isoformat(),
        "period_end": end.isoformat(),
        "sessions": int(total_sessions or 0),
        "unique_ips": int(unique_ips or 0),
        "payloads": [{"type": r[0], "count": int(r[1])} for r in payloads],
        "top_ips": [{"ip": r[0], "count": int(r[1])} for r in top_ips],
        "top_credentials": [
            {"username": r[0], "password": r[1], "count": int(r[2])} for r in combos
        ],
        "top_http_paths": [{"path": r[0], "count": int(r[1])} for r in http_targets],
        "alerts": int(alerts or 0),
    }


def _payload_chart_png(stats: dict[str, Any]) -> bytes | None:
    if plt is None:
        return None
    buckets = stats.get("payloads", [])
    if not buckets:
        return None
    fig, ax = plt.subplots(figsize=(7, 3.3))
    ax.bar([b["type"][:18] for b in buckets], [b["count"] for b in buckets], color="#00d4ff")
    ax.tick_params(axis="x", rotation=35)
    ax.set_title("Payload classifier distribution")
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    plt.close(fig)
    return buf.getvalue()


def _build_pdf_document(path: Path, stats: dict[str, Any], period_days: int) -> Path:
    if not (LETTER and colors and RLImage and inch):
        path.write_bytes(b"")
        return path

    styles = getSampleStyleSheet()
    story: list[Any] = []
    story.append(Paragraph("<b>Honeypot Threat Report</b>", styles["Title"]))
    story.append(
        Paragraph(
            f"<b>Rolling window</b>: {period_days} day(s); generated {datetime.now(timezone.utc).isoformat()}",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 12))

    story.append(Table([["Sessions", stats.get("sessions", 0)], ["Unique IPs", stats.get("unique_ips", 0)], ["Alerts", stats.get("alerts", 0)]]))

    png = _payload_chart_png(stats)
    if png:
        story.append(Spacer(1, 12))
        story.append(Paragraph("<b>Payload clustering</b>", styles["Heading2"]))
        chart_stream = io.BytesIO(png)
        story.append(RLImage(chart_stream, width=6 * inch, height=2.6 * inch))

    ips = stats.get("top_ips", [])
    if ips:
        story.append(Spacer(1, 12))
        story.append(Paragraph("<b>Top attacker IPs</b>", styles["Heading2"]))
        story.append(Table([["IP", "Count"]] + [[row["ip"], row["count"]] for row in ips]))

    doc = SimpleDocTemplate(str(path), pagesize=LETTER)
    doc.build(story)
    return path


async def generate_json_report(session: AsyncSession, period_days: int) -> ThreatReport:
    REPORTS_ROOT.mkdir(parents=True, exist_ok=True)
    stats = await _collect_stats(session, period_days)
    start, end = _window(period_days)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = REPORTS_ROOT / f"report_{period_days}d_{stamp}.json"
    json_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    pdf_path = REPORTS_ROOT / f"report_{period_days}d_{stamp}.pdf"
    _build_pdf_document(pdf_path, stats, period_days)
    record = ThreatReport(
        generated_at=datetime.now(timezone.utc),
        period_start=start,
        period_end=end,
        report_type=ReportType.summary,
        json_path=str(json_path.resolve()),
        pdf_path=str(pdf_path.resolve()),
        summary_stats={"sessions": stats["sessions"], "unique_ips": stats["unique_ips"], "alerts": stats["alerts"]},
    )
    session.add(record)
    await session.flush()
    logger.info("threat report bundle written id={}", record.id)
    return record


async def generate_pdf_report(session: AsyncSession, period_days: int) -> ThreatReport:
    return await generate_json_report(session, period_days)
