"""Built-in alerting rules."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from alerting.channels.dispatch import notify_alert

from pipeline.models import Alert, AlertSeverity, AuthAttempt, DedupeFingerprint
from pipeline.models import HoneypotSession, HttpRequest, SeenCountry


async def _dedupe_allow(db: AsyncSession, fingerprint: str) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
    res = await db.execute(
        select(DedupeFingerprint).where(
            DedupeFingerprint.key == fingerprint,
            DedupeFingerprint.created_at >= cutoff,
        )
    )
    if res.scalar_one_or_none():
        return False
    db.add(
        DedupeFingerprint(
            key=fingerprint,
            created_at=datetime.now(timezone.utc),
        )
    )
    await db.flush()
    return True


async def _record_alert(
    db: AsyncSession,
    *,
    rule_name: str,
    severity: AlertSeverity,
    description: str,
    src_ip: str,
    session_id: int | None,
    dedupe_key: str,
) -> None:
    if not await _dedupe_allow(db, dedupe_key):
        return
    alert = Alert(
        rule_name=rule_name,
        severity=severity,
        description=description,
        src_ip=src_ip,
        session_id=session_id,
        triggered_at=datetime.now(timezone.utc),
        dedupe_key=dedupe_key,
    )
    db.add(alert)
    await db.flush()
    await notify_alert(alert)


_BLOCKLIST_CACHE: tuple[float, frozenset[str]] | None = None


def _load_blocklist() -> frozenset[str]:
    global _BLOCKLIST_CACHE
    path = Path(os.getenv("BLOCKLIST_PATH", "data/blocklist.txt"))
    stat = path.stat().st_mtime if path.is_file() else 0.0
    if _BLOCKLIST_CACHE and _BLOCKLIST_CACHE[0] == stat:
        return _BLOCKLIST_CACHE[1]
    ips: set[str] = set()
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.add(line)
    frozen = frozenset(ips)
    _BLOCKLIST_CACHE = (stat, frozen)
    return frozen


def _tor_exit_set() -> frozenset[str]:
    raw = os.getenv("TOR_EXIT_IPS", "")
    return frozenset(ip.strip() for ip in raw.split(",") if ip.strip())


async def brute_force_checks(db: AsyncSession, evt: dict) -> None:
    if evt.get("channel") != "ssh_auth":
        return
    src = str(evt.get("src_ip"))
    since = datetime.now(timezone.utc) - timedelta(minutes=5)
    q = await db.execute(
        select(func.count(AuthAttempt.id))
        .join(HoneypotSession, AuthAttempt.session_id == HoneypotSession.id)
        .where(HoneypotSession.src_ip == src, AuthAttempt.timestamp >= since)
    )
    count = int(q.scalar_one())
    if count > 10:
        await _record_alert(
            db,
            rule_name="BruteForceAlert",
            severity=AlertSeverity.high,
            description=f">{count} auth attempts from {src} in 5 minutes",
            src_ip=src,
            session_id=evt.get("session_row_id"),
            dedupe_key=f"bruteforce:{src}",
        )


async def credential_stuffing_checks(db: AsyncSession, evt: dict) -> None:
    if evt.get("channel") != "ssh_auth":
        return
    src = str(evt.get("src_ip"))
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    concat_pair = AuthAttempt.username + ":" + AuthAttempt.password
    q = await db.execute(
        select(func.count(func.distinct(concat_pair)))
        .join(HoneypotSession, AuthAttempt.session_id == HoneypotSession.id)
        .where(HoneypotSession.src_ip == src, AuthAttempt.timestamp >= since)
    )
    combos = int(q.scalar_one())
    if combos > 30:
        await _record_alert(
            db,
            rule_name="CredentialStuffingAlert",
            severity=AlertSeverity.high,
            description=f"{combos} unique credential combos from {src} within 1 hour",
            src_ip=src,
            session_id=evt.get("session_row_id"),
            dedupe_key=f"credstuff:{src}",
        )


async def rce_attempt_checks(db: AsyncSession, evt: dict) -> None:
    ptype = str(evt.get("payload_type") or evt.get("attack_type") or "")
    if str(ptype).lower() != "rce":
        return
    if evt.get("channel") not in {"ssh_command", "http_request"}:
        return
    src = str(evt.get("src_ip"))
    dedupe_hour = datetime.now(timezone.utc).strftime("%Y%m%d%H")
    await _record_alert(
        db,
        rule_name="RCEAttemptAlert",
        severity=AlertSeverity.critical,
        description=f"RCE classifier triggered for traffic from {src}",
        src_ip=src,
        session_id=evt.get("session_row_id"),
        dedupe_key=f"rce:{src}:{dedupe_hour}",
    )


async def new_country_checks(db: AsyncSession, evt: dict) -> None:
    country_code = evt.get("geo", {}).get("country") if isinstance(evt.get("geo"), dict) else None
    if not country_code:
        country_code = evt.get("country")
    if not country_code:
        return
    code = str(country_code)[:4]
    if code.lower() == "private":
        return
    ip = str(evt.get("src_ip"))

    res_country = await db.execute(select(SeenCountry).where(SeenCountry.country_code == code))
    if res_country.scalar_one_or_none():
        return

    db.add(SeenCountry(country_code=code, first_seen_at=datetime.now(timezone.utc)))

    await _record_alert(
        db,
        rule_name="NewCountryAlert",
        severity=AlertSeverity.low,
        description=f"First observed attacks from country code {code} (source IP {ip})",
        src_ip=ip,
        session_id=evt.get("session_row_id"),
        dedupe_key=f"country:{code}",
    )


async def tor_exit_checks(db: AsyncSession, evt: dict) -> None:
    exits = _tor_exit_set()
    ip = str(evt.get("src_ip"))
    if not exits or ip not in exits:
        return
    await _record_alert(
        db,
        rule_name="TorExitNodeAlert",
        severity=AlertSeverity.medium,
        description=f"Connection originated from curated Tor exit {ip}",
        src_ip=ip,
        session_id=evt.get("session_row_id"),
        dedupe_key=f"tor:{ip}",
    )


async def aggressive_scan_checks(db: AsyncSession, evt: dict) -> None:
    src = str(evt.get("src_ip"))
    if evt.get("aggressive_scanner"):
        await _record_alert(
            db,
            rule_name="AggressiveScannerAlert",
            severity=AlertSeverity.medium,
            description=f"HTTP tarpit flagged aggressive bursts from {src}",
            src_ip=src,
            session_id=evt.get("session_row_id"),
            dedupe_key=f"scan:{src}",
        )
        return

    since = datetime.now(timezone.utc) - timedelta(seconds=60)
    q = await db.execute(
        select(func.count(HttpRequest.id))
        .join(HoneypotSession, HttpRequest.session_id == HoneypotSession.id)
        .where(HoneypotSession.src_ip == src, HttpRequest.timestamp >= since)
    )
    count = int(q.scalar_one())
    if count > 50:
        dedupe_hour = datetime.now(timezone.utc).strftime("%Y%m%d%H")
        await _record_alert(
            db,
            rule_name="AggressiveScannerAlert",
            severity=AlertSeverity.medium,
            description=f"{count} HTTP requests from {src} within one minute",
            src_ip=src,
            session_id=evt.get("session_row_id"),
            dedupe_key=f"burst:{src}:{dedupe_hour}",
        )


async def known_bad_ip_checks(db: AsyncSession, evt: dict) -> None:
    src = str(evt.get("src_ip"))
    if src not in _load_blocklist():
        return
    await _record_alert(
        db,
        rule_name="KnownBadIPAlert",
        severity=AlertSeverity.high,
        description=f"IP {src} appears on local/community blocklist feed",
        src_ip=src,
        session_id=evt.get("session_row_id"),
        dedupe_key=f"badip:{src}",
    )


RULE_CALLABLES = (
    brute_force_checks,
    credential_stuffing_checks,
    rce_attempt_checks,
    new_country_checks,
    tor_exit_checks,
    aggressive_scan_checks,
    known_bad_ip_checks,
)


class CallableRuleWrapper:
    def __init__(self, name: str, fn):
        self.name = name
        self._fn = fn

    async def evaluate(self, db: AsyncSession, payload: dict) -> None:
        await self._fn(db, payload)


RULES: Sequence[CallableRuleWrapper] = [
    CallableRuleWrapper(fn.__name__, fn) for fn in RULE_CALLABLES
]


ALERT_RULES = RULES
