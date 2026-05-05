"""Parse honeypot JSONL logs and persist enriched rows to SQLite."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from analytics.payloads import classify_payload, decode_payload, extract_ips, extract_urls
from alerting.engine import evaluate_ingestion_batch
from pipeline.database import get_session_factory
from pipeline.enricher import EventEnricher, heuristic_threat_boost
from pipeline.geoip import GeoIpService
from pipeline.models import (
    AuthAttempt,
    FeedEvent,
    HoneypotSession,
    HoneypotType,
    HttpRequest,
    Payload,
    ShellCommand,
)


def _parse_ts(raw: Any) -> datetime:
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(raw, tz=timezone.utc)
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)


class LogIngestor:
    def __init__(self, log_root: Path | None = None) -> None:
        self.log_root = Path(
            log_root or os.getenv("LOG_DIR", "./logs")
        ).resolve()
        self.bookmarks: dict[str, int] = {}
        self.bookmark_store = Path(
            os.getenv(
                "INGEST_STATE_PATH",
                str(self.log_root.parent / "data/ingest_state.json"),
            )
        )
        self.poll_interval = float(os.getenv("INGEST_POLL_INTERVAL_SECONDS", "2"))
        self.geo_svc = GeoIpService()
        self.enricher = EventEnricher(self.geo_svc)
        self._load_bookmarks()

    def _load_bookmarks(self) -> None:
        if self.bookmark_store.is_file():
            try:
                data = json.loads(self.bookmark_store.read_text(encoding="utf-8"))
                self.bookmarks = {k: int(v) for k, v in data.items()}
            except (json.JSONDecodeError, ValueError, OSError):
                self.bookmarks = {}

    def _save_bookmarks(self) -> None:
        try:
            self.bookmark_store.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.bookmark_store.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.bookmarks), encoding="utf-8")
            tmp.replace(self.bookmark_store)
        except OSError as exc:
            logger.warning("bookmark save failed: {}", exc)

    async def run_forever(self) -> None:
        logger.warning(
            "pipeline ingestor starting log_root=%s poll=%ss",
            self.log_root,
            self.poll_interval,
        )
        while True:
            try:
                await self._tick()
            except Exception as exc:
                logger.exception("ingest tick error: {}", exc)
            await asyncio.sleep(self.poll_interval)

    async def _tick(self) -> None:
        ssh_path = self.log_root / "ssh.jsonl"
        http_path = self.log_root / "http.jsonl"
        pending_alerts_batch: list[dict[str, Any]] = []

        factory = get_session_factory()
        async with factory() as session:
            pending_alerts_batch.extend(await self._drain_file(session, ssh_path, "ssh"))
            pending_alerts_batch.extend(await self._drain_file(session, http_path, "http"))
            await session.commit()

        await evaluate_ingestion_batch(pending_alerts_batch)

    async def _drain_file(
        self,
        session: AsyncSession,
        path: Path,
        kind: str,
    ) -> list[dict[str, Any]]:
        alert_ctx: list[dict[str, Any]] = []
        if not path.is_file():
            return alert_ctx

        offset = self.bookmarks.get(str(path), 0)
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            handle.seek(offset)
            while True:
                line = handle.readline()
                if not line:
                    break
                newline_offset = handle.tell()
                stripped = line.strip()
                if not stripped:
                    self.bookmarks[str(path)] = newline_offset
                    continue
                try:
                    evt = json.loads(stripped)
                    ctx = await self._handle_event(session, evt, kind)
                    if ctx:
                        alert_ctx.append(ctx)
                except json.JSONDecodeError:
                    logger.warning("skipping malformed json from {}", path.name)
                self.bookmarks[str(path)] = newline_offset

        self._save_bookmarks()
        return alert_ctx

    async def _handle_event(
        self,
        session: AsyncSession,
        evt: dict[str, Any],
        default_kind: str,
    ) -> dict[str, Any] | None:
        honeypot = evt.get("honeypot", default_kind)
        event_name = evt.get("event")

        enriched = await self.enricher.enrich_ip(str(evt.get("src_ip", "0.0.0.0")), evt)

        geo = enriched.get("geo", {})
        if honeypot == "ssh":
            return await self._handle_ssh(session, enriched, geo, event_name)
        return await self._handle_http(session, enriched, geo, event_name)

    async def _get_or_create_session(
        self,
        session: AsyncSession,
        *,
        honeypot: str,
        external_id: str,
        evt: dict[str, Any],
        geo: dict[str, Any],
    ) -> HoneypotSession:
        htype = HoneypotType.ssh if honeypot == "ssh" else HoneypotType.http
        res = await session.execute(
            select(HoneypotSession).where(
                HoneypotSession.external_session_id == external_id,
                HoneypotSession.honeypot_type == htype,
            )
        )
        row = res.scalar_one_or_none()
        started = _parse_ts(evt.get("timestamp"))
        if row:
            return row

        threat = heuristic_threat_boost(evt) + min(int(evt.get("threat_hint", 0)), 60)
        row = HoneypotSession(
            honeypot_type=htype,
            external_session_id=external_id or None,
            src_ip=str(evt.get("src_ip", "127.0.0.1")),
            src_port=evt.get("src_port"),
            country=geo.get("country"),
            city=geo.get("city"),
            asn=int(geo["asn"]) if geo.get("asn") is not None else None,
            isp=geo.get("isp"),
            latitude=float(geo["latitude"]) if geo.get("latitude") is not None else None,
            longitude=float(geo["longitude"]) if geo.get("longitude") is not None else None,
            started_at=started,
            duration_seconds=None,
            is_tor=bool(evt.get("is_tor")),
            is_vpn=bool(evt.get("is_vpn")),
            threat_score=min(threat, 100),
        )
        session.add(row)
        await session.flush()
        return row

    async def _insert_feed(self, session: AsyncSession, **kwargs: Any) -> None:
        session.add(FeedEvent(**kwargs))

    async def _handle_ssh(
        self,
        session: AsyncSession,
        evt: dict[str, Any],
        geo: dict[str, Any],
        event_name: str | None,
    ) -> dict[str, Any] | None:
        external_id = str(evt.get("session_id") or evt.get("id") or "unknown-session")
        row = await self._get_or_create_session(
            session,
            honeypot="ssh",
            external_id=external_id,
            evt=evt,
            geo=geo,
        )
        alert_ctx: dict[str, Any] | None = None

        if event_name in {"ssh_auth", "auth", "credential"}:
            session.add(
                AuthAttempt(
                    session_id=row.id,
                    username=str(evt.get("username", "")),
                    password=str(evt.get("password", "")),
                    attempt_number=int(evt.get("attempt_number", 1)),
                    timestamp=_parse_ts(evt.get("timestamp")),
                    success=False,
                )
            )
            await self._insert_feed(
                session,
                event_type="auth",
                detail=f"{evt.get('username')} / ***",
                src_ip=row.src_ip,
                country=row.country,
                honeypot_type="ssh",
                timestamp=_parse_ts(evt.get("timestamp")),
            )
            alert_ctx = {
                "channel": "ssh_auth",
                "src_ip": row.src_ip,
                "timestamp": _parse_ts(evt.get("timestamp")),
                "attempt": evt,
                "session_row_id": row.id,
                "geo": geo,
                "country": geo.get("country"),
            }

        elif event_name in {"ssh_command", "command"}:
            full_cmd = str(evt.get("full_line") or evt.get("command") or "")
            classify_val = classify_payload(full_cmd).value
            is_mal = classify_val != "benign"
            cmd_text = evt.get("command") or full_cmd
            cmd_text = cmd_text[:4096]
            session.add(
                ShellCommand(
                    session_id=row.id,
                    command=str(cmd_text)[:512],
                    arguments=str(evt.get("arguments") or ""),
                    timestamp=_parse_ts(evt.get("timestamp")),
                    is_malicious=is_mal,
                    malicious_category=classify_val,
                )
            )
            urls = extract_urls(full_cmd)
            ips = extract_ips(full_cmd)
            decoded = decode_payload(full_cmd)
            sev_map = {"rce": "critical", "sql_injection": "high", "xss": "medium"}
            severity = sev_map.get(classify_val, "low")
            session.add(
                Payload(
                    session_id=row.id,
                    raw_payload=full_cmd[:8192],
                    payload_type=classify_val,
                    decoded_payload=decoded,
                    extracted_urls=urls,
                    extracted_ips=ips,
                    severity=severity,
                )
            )
            await self._insert_feed(
                session,
                event_type="ssh_command",
                detail=full_cmd[:512],
                src_ip=row.src_ip,
                country=row.country,
                honeypot_type="ssh",
                timestamp=_parse_ts(evt.get("timestamp")),
            )
            alert_ctx = {
                "channel": "ssh_command",
                "payload_type": classify_val,
                "full_cmd": full_cmd,
                "src_ip": row.src_ip,
                "timestamp": _parse_ts(evt.get("timestamp")),
                "session_row_id": row.id,
                "geo": geo,
                "country": geo.get("country"),
            }

        elif event_name in {"ssh_download", "download"}:
            url = str(evt.get("url") or "")
            classify_val = classify_payload(url).value
            session.add(
                Payload(
                    session_id=row.id,
                    raw_payload=url,
                    payload_type="download_attempt",
                    decoded_payload=decode_payload(url),
                    extracted_urls=[url],
                    extracted_ips=extract_ips(url),
                    severity="medium",
                )
            )
            await self._insert_feed(
                session,
                event_type="download",
                detail=url[:512],
                src_ip=row.src_ip,
                country=row.country,
                honeypot_type="ssh",
                timestamp=_parse_ts(evt.get("timestamp")),
            )
            alert_ctx = {
                "channel": "download",
                "url": url,
                "src_ip": row.src_ip,
                "session_row_id": row.id,
                "geo": geo,
                "country": geo.get("country"),
            }

        elif event_name in {"ssh_session_end", "session_end"}:
            ended = _parse_ts(evt.get("timestamp"))
            if row.started_at:
                row.duration_seconds = max(
                    0.0,
                    (ended - row.started_at).total_seconds(),
                )
            row.ended_at = ended
            boost = heuristic_threat_boost(evt)
            row.threat_score = min(100, int(row.threat_score or 0) + boost)
            alert_ctx = {
                "channel": "session_closed",
                "honeypot": "ssh",
                "src_ip": row.src_ip,
                "duration": row.duration_seconds,
                "session_commands": evt.get("commands") or evt.get("all_commands"),
                "geo": geo,
                "country": geo.get("country"),
                "session_row_id": row.id,
            }

        else:
            await self._insert_feed(
                session,
                event_type=str(event_name or "ssh_unknown"),
                detail=json.dumps(evt)[:2048],
                src_ip=row.src_ip,
                country=row.country,
                honeypot_type="ssh",
                timestamp=_parse_ts(evt.get("timestamp")),
            )

        row.threat_score = min(
            100,
            int(row.threat_score or 0) + heuristic_threat_boost(evt),
        )
        return alert_ctx

    async def _handle_http(
        self,
        session: AsyncSession,
        evt: dict[str, Any],
        geo: dict[str, Any],
        event_name: str | None,
    ) -> dict[str, Any] | None:
        external_id = str(
            evt.get("session_id")
            or f"{evt.get('src_ip')}:{evt.get('fingerprint','http')}"
        )
        row = await self._get_or_create_session(
            session,
            honeypot="http",
            external_id=external_id,
            evt=evt,
            geo=geo,
        )
        method = str(evt.get("method", "GET")).upper()
        path = str(evt.get("path", "/"))
        body_val = evt.get("body") or evt.get("post_body") or ""
        body_text = "" if body_val is None else str(body_val)

        ua = evt.get("user_agent")
        headers = evt.get("headers") or {}
        if not ua:
            ua = headers.get("User-Agent") or headers.get("user-agent")

        classify_val_raw = evt.get("attack_type")
        if classify_val_raw:
            classify_val = str(classify_val_raw)
        else:
            classify_val = classify_payload(f"{method} {path} {body_text}").value

        is_scanner = bool(evt.get("is_scanner"))
        scanner_tool = evt.get("scanner_tool")
        code = int(evt.get("response_code") or evt.get("status") or 200)

        session.add(
            HttpRequest(
                session_id=row.id,
                method=method,
                path=path,
                query_string=evt.get("query_string"),
                body=body_text or None,
                user_agent=str(ua) if ua else None,
                attack_type=str(classify_val),
                is_scanner=is_scanner,
                scanner_tool=scanner_tool,
                timestamp=_parse_ts(evt.get("timestamp")),
                response_code=code,
            )
        )

        combined = f"{path} {body_text}"
        ptype = classify_payload(combined).value
        urls = extract_urls(combined)
        ips = extract_ips(combined)
        decoded = decode_payload(combined)

        severity = evt.get("payload_severity")
        if not severity:
            if ptype == "rce":
                severity = "critical"
            elif ptype in {"sql_injection", "lfi"}:
                severity = "high"
            elif ptype in {"path_traversal", "xss", "ssrf"}:
                severity = "medium"
            else:
                severity = "low"

        session.add(
            Payload(
                session_id=row.id,
                raw_payload=combined[:8192],
                payload_type=str(ptype),
                decoded_payload=decoded,
                extracted_urls=urls,
                extracted_ips=ips,
                severity=str(severity),
            )
        )

        await self._insert_feed(
            session,
            event_type=str(event_name or "http_request"),
            detail=f"{method} {path}",
            src_ip=row.src_ip,
            country=row.country,
            honeypot_type="http",
            timestamp=_parse_ts(evt.get("timestamp")),
        )

        row.threat_score = min(
            100,
            int(row.threat_score or 0)
            + heuristic_threat_boost(evt | {"attack_type": classify_val}),
        )

        alert_ctx = {
            "channel": "http_request",
            "src_ip": row.src_ip,
            "attack_type": classify_val,
            "path": path,
            "scanner": is_scanner,
            "aggressive_scanner": bool(evt.get("aggressive_scanner")),
            "timestamp": _parse_ts(evt.get("timestamp")),
            "session_row_id": row.id,
            "geo": geo,
            "country": geo.get("country"),
        }
        return alert_ctx


async def main_async() -> None:
    from pipeline.database import init_models

    await init_models()
    await LogIngestor().run_forever()


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
