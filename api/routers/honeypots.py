"""Synthetic honeypot posture pulled from live telemetry + declared ports."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import get_current_user, get_db_session
from api.schemas import HoneypotStatusRow
from pipeline.models import FeedEvent, HoneypotSession, HoneypotType

router = APIRouter(prefix="/honeypots", tags=["honeypots"])


@router.get("/status", response_model=list[HoneypotStatusRow])
async def honeypot_status(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    _: Annotated[str, Depends(get_current_user)],
) -> list[HoneypotStatusRow]:
    now = datetime.now(timezone.utc)
    midnight = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)

    ssh_today = await db.scalar(
        select(func.count())
        .select_from(HoneypotSession)
        .where(HoneypotSession.honeypot_type == HoneypotType.ssh, HoneypotSession.started_at >= midnight)
    )
    http_today = await db.scalar(
        select(func.count())
        .select_from(HoneypotSession)
        .where(HoneypotSession.honeypot_type == HoneypotType.http, HoneypotSession.started_at >= midnight)
    )

    ssh_last = await db.scalar(select(func.max(FeedEvent.timestamp)).where(FeedEvent.honeypot_type == "ssh"))
    http_last = await db.scalar(select(func.max(FeedEvent.timestamp)).where(FeedEvent.honeypot_type == "http"))

    ssh_port = int(os.getenv("SSH_HONEYPOT_PORT", "2222"))
    http_port = int(os.getenv("HTTP_HONEYPOT_PORT", "8080"))

    return [
        HoneypotStatusRow(
            type="ssh",
            status="up",
            port=ssh_port,
            sessions_today=int(ssh_today or 0),
            uptime_seconds=86400.0,
            last_event_at=ssh_last,
        ),
        HoneypotStatusRow(
            type="http",
            status="up",
            port=http_port,
            sessions_today=int(http_today or 0),
            uptime_seconds=86400.0,
            last_event_at=http_last,
        ),
    ]
