"""Payload discovery & classification listings."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import get_current_user, get_db_session
from api.schemas import PayloadListItem, PayloadListResponse, PayloadStatsResponse
from pipeline.models import HoneypotSession, Payload

router = APIRouter(prefix="/payloads", tags=["payloads"])


def _filtered_payload_query(
    *,
    payload_type: str | None,
    severity: str | None,
):
    stmt = select(Payload, HoneypotSession.src_ip, HoneypotSession.started_at).join(
        HoneypotSession, Payload.session_id == HoneypotSession.id
    )
    if payload_type:
        stmt = stmt.where(Payload.payload_type == payload_type)
    if severity:
        stmt = stmt.where(Payload.severity == severity)
    return stmt


@router.get("", response_model=PayloadListResponse)
async def list_payloads(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    _: Annotated[str, Depends(get_current_user)],
    payload_type: str | None = None,
    severity: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
) -> PayloadListResponse:
    base = _filtered_payload_query(payload_type=payload_type, severity=severity)
    inner = base.subquery()
    total = await db.scalar(select(func.count()).select_from(inner))

    rows = (
        (
            await db.execute(
                base.order_by(Payload.id.desc()).offset((page - 1) * page_size).limit(page_size)
            )
        )
        .all()
    )

    items = [
        PayloadListItem(
            id=payload.id,
            session_id=payload.session_id,
            src_ip=str(src_ip),
            payload_type=payload.payload_type,
            severity=payload.severity,
            raw_payload=payload.raw_payload[:1024],
            decoded_payload=payload.decoded_payload,
            timestamp=sess_started,
        )
        for payload, src_ip, sess_started in rows
    ]

    return PayloadListResponse(
        items=items,
        total=int(total or 0),
        page=page,
        page_size=page_size,
    )


@router.get("/stats", response_model=PayloadStatsResponse)
async def payload_stats(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    _: Annotated[str, Depends(get_current_user)],
) -> PayloadStatsResponse:
    type_rows = (
        (await db.execute(select(Payload.payload_type, func.count()).group_by(Payload.payload_type)))
        .all()
    )
    sev_rows = (
        (await db.execute(select(Payload.severity, func.count()).group_by(Payload.severity))).all()
    )
    by_type = {str(t): int(c) for t, c in type_rows}
    by_severity = {str(s): int(c) for s, c in sev_rows}
    return PayloadStatsResponse(by_type=by_type, by_severity=by_severity)
