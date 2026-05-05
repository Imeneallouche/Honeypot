"""Session listing and drill-down APIs."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.dependencies import get_current_user, get_db_session
from api.schemas import (
    AuthAttemptOut,
    HttpRequestOut,
    PayloadOut,
    SessionDetailResponse,
    SessionListItem,
    SessionListResponse,
    ShellCommandOut,
)
from pipeline.models import (
    AuthAttempt,
    HoneypotSession,
    HoneypotType,
    HttpRequest,
    Payload,
    ShellCommand,
)

router = APIRouter(prefix="/sessions", tags=["sessions"])


def _apply_filters(
    stmt,
    *,
    honeypot_type: str | None,
    country: list[str] | None,
    start: datetime | None,
    end: datetime | None,
    min_threat_score: int | None,
    is_acknowledged: bool | None,
):
    if honeypot_type:
        try:
            typed = HoneypotType(honeypot_type)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid honeypot type") from exc
        stmt = stmt.where(HoneypotSession.honeypot_type == typed)
    if country:
        stmt = stmt.where(HoneypotSession.country.in_(country))
    if start:
        stmt = stmt.where(HoneypotSession.started_at >= start)
    if end:
        stmt = stmt.where(HoneypotSession.started_at <= end)
    if min_threat_score is not None:
        stmt = stmt.where(HoneypotSession.threat_score >= min_threat_score)
    if is_acknowledged is not None:
        stmt = stmt.where(HoneypotSession.is_acknowledged.is_(is_acknowledged))
    return stmt


@router.get("", response_model=SessionListResponse)
async def list_sessions(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    _: Annotated[str, Depends(get_current_user)],
    honeypot_type: str | None = None,
    country: list[str] | None = Query(None),
    start: datetime | None = None,
    end: datetime | None = None,
    min_threat_score: int | None = None,
    is_acknowledged: bool | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
) -> SessionListResponse:
    base = select(HoneypotSession)
    base = _apply_filters(
        base,
        honeypot_type=honeypot_type,
        country=country,
        start=start,
        end=end,
        min_threat_score=min_threat_score,
        is_acknowledged=is_acknowledged,
    )

    total = await db.scalar(select(func.count()).select_from(base.subquery()))

    page_stmt = (
        base.order_by(HoneypotSession.started_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    sessions = (await db.execute(page_stmt)).scalars().all()

    items: list[SessionListItem] = []
    for sess in sessions:
        cmd_total = await db.scalar(select(func.count()).where(ShellCommand.session_id == sess.id)) or 0
        http_total = await db.scalar(select(func.count()).where(HttpRequest.session_id == sess.id)) or 0
        items.append(
            SessionListItem(
                id=sess.id,
                honeypot_type=sess.honeypot_type.value,
                src_ip=sess.src_ip,
                src_port=sess.src_port,
                country=sess.country,
                city=sess.city,
                started_at=sess.started_at,
                ended_at=sess.ended_at,
                duration_seconds=float(sess.duration_seconds) if sess.duration_seconds is not None else None,
                threat_score=int(sess.threat_score or 0),
                is_acknowledged=bool(sess.is_acknowledged),
                commands_count=int(cmd_total),
                http_requests_count=int(http_total),
            )
        )

    return SessionListResponse(items=items, total=int(total or 0), page=page, page_size=page_size)


@router.get("/{session_id}", response_model=SessionDetailResponse)
async def session_detail(
    session_id: int,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    _: Annotated[str, Depends(get_current_user)],
) -> SessionDetailResponse:
    stmt = (
        select(HoneypotSession)
        .where(HoneypotSession.id == session_id)
        .options(
            selectinload(HoneypotSession.auth_attempts),
            selectinload(HoneypotSession.shell_commands),
            selectinload(HoneypotSession.http_requests),
            selectinload(HoneypotSession.payloads),
        )
    )

    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Session not found")

    cmd_total = await db.scalar(select(func.count()).where(ShellCommand.session_id == row.id)) or 0
    http_total = await db.scalar(select(func.count()).where(HttpRequest.session_id == row.id)) or 0

    session_item = SessionListItem(
        id=row.id,
        honeypot_type=row.honeypot_type.value,
        src_ip=row.src_ip,
        src_port=row.src_port,
        country=row.country,
        city=row.city,
        started_at=row.started_at,
        ended_at=row.ended_at,
        duration_seconds=float(row.duration_seconds) if row.duration_seconds is not None else None,
        threat_score=int(row.threat_score or 0),
        is_acknowledged=bool(row.is_acknowledged),
        commands_count=int(cmd_total),
        http_requests_count=int(http_total),
    )

    auths = [
        AuthAttemptOut(
            id=a.id,
            username=a.username,
            password=a.password,
            attempt_number=a.attempt_number,
            timestamp=a.timestamp,
            success=a.success,
        )
        for a in sorted(row.auth_attempts, key=lambda x: x.timestamp)
    ]
    cmds = [
        ShellCommandOut(
            id=c.id,
            command=c.command,
            arguments=c.arguments,
            timestamp=c.timestamp,
            is_malicious=c.is_malicious,
            malicious_category=c.malicious_category,
        )
        for c in sorted(row.shell_commands, key=lambda x: x.timestamp)
    ]
    reqs = [
        HttpRequestOut(
            id=h.id,
            method=h.method,
            path=h.path,
            query_string=h.query_string,
            body=h.body,
            user_agent=h.user_agent,
            attack_type=h.attack_type,
            is_scanner=h.is_scanner,
            scanner_tool=h.scanner_tool,
            timestamp=h.timestamp,
            response_code=h.response_code,
        )
        for h in sorted(row.http_requests, key=lambda x: x.timestamp)
    ]
    pays = [
        PayloadOut(
            id=p.id,
            raw_payload=p.raw_payload,
            payload_type=p.payload_type,
            decoded_payload=p.decoded_payload,
            extracted_urls=list(p.extracted_urls) if isinstance(p.extracted_urls, list) else [],
            extracted_ips=list(p.extracted_ips) if isinstance(p.extracted_ips, list) else [],
            severity=p.severity,
        )
        for p in sorted(row.payloads, key=lambda x: x.id)
    ]

    return SessionDetailResponse(
        session=session_item,
        auth_attempts=auths,
        shell_commands=cmds,
        http_requests=reqs,
        payloads=pays,
        latitude=row.latitude,
        longitude=row.longitude,
    )
