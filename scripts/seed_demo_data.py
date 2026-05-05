#!/usr/bin/env python3
"""Insert synthetic sessions and feed rows for UI demos."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./data/honeypot.db")

from pipeline.database import get_session_factory, init_models  # noqa: E402
from pipeline.models import (  # noqa: E402
    AuthAttempt,
    FeedEvent,
    HoneypotSession,
    HoneypotType,
    HttpRequest,
    Payload,
    ShellCommand,
)


async def _session_exists(db, external_id: str, htype: HoneypotType) -> bool:
    res = await db.execute(
        select(HoneypotSession.id).where(
            HoneypotSession.external_session_id == external_id,
            HoneypotSession.honeypot_type == htype,
        )
    )
    return res.scalar_one_or_none() is not None


async def main() -> None:
    await init_models()
    factory = get_session_factory()
    now = datetime.now(timezone.utc)

    async with factory() as db:
        ext_ssh = "demo-seed-ssh"
        if not await _session_exists(db, ext_ssh, HoneypotType.ssh):
            ssh_row = HoneypotSession(
                honeypot_type=HoneypotType.ssh,
                external_session_id=ext_ssh,
                src_ip="203.0.113.50",
                src_port=43210,
                country="US",
                city="Demo City",
                started_at=now - timedelta(hours=2),
                threat_score=42,
            )
            db.add(ssh_row)
            await db.flush()
            db.add(
                AuthAttempt(
                    session_id=ssh_row.id,
                    username="root",
                    password="admin123",
                    attempt_number=1,
                    timestamp=now - timedelta(hours=2),
                    success=False,
                )
            )
            db.add(
                ShellCommand(
                    session_id=ssh_row.id,
                    command="uname",
                    arguments="-a",
                    timestamp=now - timedelta(hours=1, minutes=55),
                    is_malicious=False,
                    malicious_category="benign",
                )
            )
            db.add(
                FeedEvent(
                    event_type="auth",
                    detail="root / ***",
                    src_ip=ssh_row.src_ip,
                    country=ssh_row.country,
                    honeypot_type="ssh",
                    timestamp=now - timedelta(hours=2),
                )
            )

        ext_http = "demo-seed-http"
        if not await _session_exists(db, ext_http, HoneypotType.http):
            http_row = HoneypotSession(
                honeypot_type=HoneypotType.http,
                external_session_id=ext_http,
                src_ip="198.51.100.20",
                src_port=60444,
                country="DE",
                city="Berlin",
                started_at=now - timedelta(hours=1),
                threat_score=65,
            )
            db.add(http_row)
            await db.flush()
            db.add(
                HttpRequest(
                    session_id=http_row.id,
                    method="GET",
                    path="/cgi-bin/luci/;stok=/locale",
                    query_string=None,
                    body=None,
                    user_agent="curl/8.0",
                    attack_type="lfi",
                    is_scanner=True,
                    scanner_tool="curl",
                    timestamp=now - timedelta(minutes=50),
                    response_code=404,
                )
            )
            db.add(
                Payload(
                    session_id=http_row.id,
                    raw_payload="/etc/passwd",
                    payload_type="path_traversal",
                    decoded_payload=None,
                    extracted_urls=None,
                    extracted_ips=None,
                    severity="high",
                )
            )
            db.add(
                FeedEvent(
                    event_type="http_request",
                    detail="GET /cgi-bin/...",
                    src_ip=http_row.src_ip,
                    country=http_row.country,
                    honeypot_type="http",
                    timestamp=now - timedelta(minutes=50),
                )
            )

        await db.commit()
    print("seed_demo_data: done")


if __name__ == "__main__":
    asyncio.run(main())
