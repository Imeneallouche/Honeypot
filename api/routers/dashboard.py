"""Dashboard KPI routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import get_current_user, get_db_session
from api.schemas import HourlyCount, LiveTickerStat, OverviewStatsResponse
from pipeline.models import Alert, AuthAttempt, FeedEvent, HoneypotSession, HoneypotType

router = APIRouter(prefix="/stats", tags=["dashboard"])


@router.get("/overview", response_model=OverviewStatsResponse)
async def stats_overview(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    _: Annotated[str, Depends(get_current_user)],
) -> OverviewStatsResponse:
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)
    hour_ago = now - timedelta(hours=24)

    total_24 = await db.scalar(select(func.count()).select_from(HoneypotSession).where(HoneypotSession.started_at >= day_ago))
    total_7 = await db.scalar(select(func.count()).select_from(HoneypotSession).where(HoneypotSession.started_at >= week_ago))
    total_30 = await db.scalar(select(func.count()).select_from(HoneypotSession).where(HoneypotSession.started_at >= month_ago))

    unique_ips = await db.scalar(
        select(func.count(distinct(HoneypotSession.src_ip)))
        .select_from(HoneypotSession)
        .where(HoneypotSession.started_at >= day_ago)
    )

    country_row = await db.execute(
        select(HoneypotSession.country, func.count().label("c"))
        .where(HoneypotSession.country.is_not(None))
        .group_by(HoneypotSession.country)
        .order_by(func.count().desc())
        .limit(1)
    )
    top_country = country_row.one_or_none()
    country_name = str(top_country[0]) if top_country else None

    user_row = await db.execute(
        select(AuthAttempt.username, func.count().label("c"))
        .join(HoneypotSession, AuthAttempt.session_id == HoneypotSession.id)
        .where(AuthAttempt.timestamp >= month_ago)
        .group_by(AuthAttempt.username)
        .order_by(func.count().desc())
        .limit(1)
    )
    tup_user = user_row.one_or_none()
    top_user = str(tup_user[0]) if tup_user else None

    pass_row = await db.execute(
        select(AuthAttempt.password, func.count().label("c"))
        .join(HoneypotSession, AuthAttempt.session_id == HoneypotSession.id)
        .where(AuthAttempt.timestamp >= month_ago)
        .group_by(AuthAttempt.password)
        .order_by(func.count().desc())
        .limit(1)
    )
    tup_pass = pass_row.one_or_none()
    top_password = str(tup_pass[0]) if tup_pass else None

    active_sessions = await db.scalar(
        select(func.count())
        .select_from(HoneypotSession)
        .where(HoneypotSession.ended_at.is_(None), HoneypotSession.started_at >= day_ago)
    )

    unacked = await db.scalar(
        select(func.count()).select_from(Alert).where(Alert.is_acknowledged.is_(False))
    )

    ssh_count = await db.scalar(
        select(func.count()).select_from(HoneypotSession).where(HoneypotSession.honeypot_type == HoneypotType.ssh)
    )
    http_count = await db.scalar(
        select(func.count()).select_from(HoneypotSession).where(HoneypotSession.honeypot_type == HoneypotType.http)
    )

    hourly_rows = (
        (
            await db.execute(
                select(
                    func.strftime("%Y-%m-%d %H:00", HoneypotSession.started_at).label("hour"),
                    func.count().label("count"),
                )
                .where(HoneypotSession.started_at >= hour_ago)
                .group_by("hour")
                .order_by("hour")
            )
        )
        .all()
    )
    hourly: list[HourlyCount] = [HourlyCount(hour=str(row[0]), count=int(row[1])) for row in hourly_rows if row[0]]

    breakdown = {"ssh": int(ssh_count or 0), "http": int(http_count or 0)}

    return OverviewStatsResponse(
        total_sessions_24h=int(total_24 or 0),
        total_sessions_7d=int(total_7 or 0),
        total_sessions_30d=int(total_30 or 0),
        unique_ips_24h=int(unique_ips or 0),
        top_country=country_name,
        top_username=top_user,
        top_password=top_password,
        active_sessions_now=int(active_sessions or 0),
        alerts_unacknowledged=int(unacked or 0),
        attack_types_breakdown=breakdown,
        sessions_per_hour_last_24h=hourly,
    )


@router.get("/live", response_model=LiveTickerStat)
async def stats_live(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    _: Annotated[str, Depends(get_current_user)],
) -> LiveTickerStat:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=60)
    evt_count = await db.scalar(select(func.count()).select_from(FeedEvent).where(FeedEvent.timestamp >= cutoff))
    ip_stmt = (
        select(func.count(distinct(FeedEvent.src_ip)))
        .select_from(FeedEvent)
        .where(FeedEvent.timestamp >= cutoff)
    )
    uniq_ips = await db.scalar(ip_stmt)
    newest = await db.scalar(select(FeedEvent.timestamp).order_by(FeedEvent.timestamp.desc()).limit(1))
    return LiveTickerStat(events_last_60s=int(evt_count or 0), unique_ips_last_60s=int(uniq_ips or 0), newest_event_at=newest)
