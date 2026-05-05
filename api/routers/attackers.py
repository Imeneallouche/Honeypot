"""Attacker-centric intelligence aggregation."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import get_current_user, get_db_session
from api.schemas import (
    AttackerProfileResponse,
    AuthAttemptOut,
    PayloadOut,
    SessionListItem,
    ShellCommandOut,
    TopCountryRow,
    TopIpRow,
)
from pipeline.models import (
    AuthAttempt,
    HoneypotSession,
    HttpRequest,
    Payload,
    ShellCommand,
)

router = APIRouter(prefix="/attackers", tags=["attackers"])


def _flag_from_country(label: str | None) -> str:
    if not label or len(label) < 2:
        return ""
    core = "".join(ch for ch in label[:6] if ch.isalpha())[:2]
    if len(core) != 2:
        return ""
    a, b = core.upper()
    if not ("A" <= a <= "Z" and "A" <= b <= "Z"):
        return ""
    return chr(ord(a) + 127397) + chr(ord(b) + 127397)


@router.get("/top-ips", response_model=list[TopIpRow])
async def top_ips(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    _: Annotated[str, Depends(get_current_user)],
    limit: int = 50,
) -> list[TopIpRow]:
    rows = (
        (
            await db.execute(
                select(
                    HoneypotSession.src_ip,
                    func.max(HoneypotSession.country).label("country"),
                    func.count().label("hits"),
                    func.max(HoneypotSession.threat_score).label("threat_score"),
                    func.max(HoneypotSession.started_at).label("last_seen"),
                )
                .group_by(HoneypotSession.src_ip)
                .order_by(func.count().desc())
                .limit(limit)
            )
        )
        .all()
    )
    results: list[TopIpRow] = []
    for ip, country, hits, thr, last in rows:
        results.append(
            TopIpRow(
                ip=str(ip),
                count=int(hits),
                country=str(country) if country else None,
                flag=_flag_from_country(str(country)),
                threat_score=int(thr or 0),
                last_seen=last,
            )
        )
    return results


@router.get("/top-countries", response_model=list[TopCountryRow])
async def top_countries(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    _: Annotated[str, Depends(get_current_user)],
    limit: int = 40,
) -> list[TopCountryRow]:
    total = await db.scalar(select(func.count()).select_from(HoneypotSession))
    rows = (
        (
            await db.execute(
                select(HoneypotSession.country, func.count().label("hits"))
                .where(HoneypotSession.country.is_not(None))
                .group_by(HoneypotSession.country)
                .order_by(func.count().desc())
                .limit(limit)
            )
        )
        .all()
    )

    denom = float(total or 1)
    out: list[TopCountryRow] = []
    for country, hits in rows:
        count = int(hits)
        pct = round(100.0 * count / denom, 2)
        out.append(
            TopCountryRow(
                country=str(country),
                count=count,
                flag=_flag_from_country(str(country)),
                percentage=pct,
            )
        )
    return out


@router.get("/{ip}", response_model=AttackerProfileResponse)
async def attacker_profile(
    ip: str,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    _: Annotated[str, Depends(get_current_user)],
) -> AttackerProfileResponse:
    sessions = (
        (await db.execute(select(HoneypotSession).where(HoneypotSession.src_ip == ip)))
        .scalars()
        .all()
    )
    if not sessions:
        raise HTTPException(status_code=404, detail="No sessions for IP")

    session_items: list[SessionListItem] = []
    for sess in sessions:
        cmd_total = await db.scalar(select(func.count()).where(ShellCommand.session_id == sess.id)) or 0
        http_total = await db.scalar(select(func.count()).where(HttpRequest.session_id == sess.id)) or 0
        session_items.append(
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

    ids = [s.id for s in sessions]
    cmds_db = (
        (await db.execute(select(ShellCommand).where(ShellCommand.session_id.in_(ids))))
        .scalars()
        .all()
    )
    creds_db = (
        (await db.execute(select(AuthAttempt).where(AuthAttempt.session_id.in_(ids))))
        .scalars()
        .all()
    )
    pays_db = (
        (await db.execute(select(Payload).where(Payload.session_id.in_(ids))))
        .scalars()
        .all()
    )

    cmds = [
        ShellCommandOut(
            id=c.id,
            command=c.command,
            arguments=c.arguments,
            timestamp=c.timestamp,
            is_malicious=c.is_malicious,
            malicious_category=c.malicious_category,
        )
        for c in sorted(cmds_db, key=lambda x: x.timestamp)
    ]
    creds = [
        AuthAttemptOut(
            id=a.id,
            username=a.username,
            password=a.password,
            attempt_number=a.attempt_number,
            timestamp=a.timestamp,
            success=a.success,
        )
        for a in sorted(creds_db, key=lambda x: x.timestamp)
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
        for p in sorted(pays_db, key=lambda x: x.id)
    ]

    latest_threat = max((int(s.threat_score or 0) for s in sessions), default=0)

    return AttackerProfileResponse(
        ip=ip,
        sessions=session_items,
        commands=cmds,
        credentials=creds,
        payloads=pays,
        threat_score_latest=latest_threat,
    )
