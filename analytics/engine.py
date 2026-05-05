"""Periodic analytics coordinator (maintains aggregates and alert sweeps)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from loguru import logger
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from alerting.engine import evaluate_periodic_signals
from pipeline.database import get_session_factory
from pipeline.models import AuthAttempt, FeedEvent, HoneypotSession, Payload


async def run_analytics_cycle() -> None:
    """Single scheduled pass — best-effort session scoring refresh + outbound alert sweep."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            await _adjust_threat_scores(session)
            await _trim_old_feed_events(session)
            await session.commit()
        except Exception as exc:
            await session.rollback()
            logger.exception("analytics cycle failed before alert sweep {}", exc)

    await evaluate_periodic_signals()


async def _adjust_threat_scores(session: AsyncSession) -> None:
    """Bump threat scores modestly based on payloads and brute-force bursts (last 60 min)."""
    window = datetime.now(timezone.utc) - timedelta(hours=1)
    brute_subq = (
        select(AuthAttempt.session_id.label("sid"), func.count(AuthAttempt.id).label("hits"))
        .join(HoneypotSession, HoneypotSession.id == AuthAttempt.session_id)
        .where(AuthAttempt.timestamp >= window)
        .group_by(AuthAttempt.session_id)
        .having(func.count(AuthAttempt.id) >= 15)
        .subquery()
    )
    brute_ids = (await session.execute(select(brute_subq.c.sid))).scalars().all()
    for sid in brute_ids:
        row = await session.get(HoneypotSession, sid)
        if row is not None:
            row.threat_score = min(100, int(row.threat_score or 0) + 10)

    crit_rows = (
        (
            await session.execute(
                select(Payload.session_id)
                .where(
                    Payload.severity.in_(("critical", "high")),
                )
                .distinct()
            )
        )
        .scalars()
        .all()
    )
    for sid in crit_rows:
        row = await session.get(HoneypotSession, sid)
        if row is not None:
            row.threat_score = min(100, int(row.threat_score or 0) + 15)


async def _trim_old_feed_events(session: AsyncSession) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=14)
    await session.execute(delete(FeedEvent).where(FeedEvent.timestamp < cutoff))
