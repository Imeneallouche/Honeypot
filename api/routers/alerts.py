"""Alert triage endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import get_current_user, get_db_session
from api.schemas import AlertItem, AlertListResponse, AlertRuleInfo
from pipeline.models import Alert, AlertSeverity

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _serialize(alert: Alert) -> AlertItem:
    return AlertItem(
        id=alert.id,
        rule_name=alert.rule_name,
        severity=alert.severity.value if isinstance(alert.severity, AlertSeverity) else str(alert.severity),
        description=alert.description,
        src_ip=alert.src_ip,
        session_id=alert.session_id,
        triggered_at=alert.triggered_at,
        is_acknowledged=alert.is_acknowledged,
        acknowledged_at=alert.acknowledged_at,
    )


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    _: Annotated[str, Depends(get_current_user)],
    severity: str | None = None,
    acknowledged: bool | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
) -> AlertListResponse:
    stmt = select(Alert)
    if severity:
        lookup = {member.value.upper(): member for member in AlertSeverity}
        sev = lookup.get(severity.upper())
        if sev is None:
            raise HTTPException(status_code=400, detail="Invalid severity")
        stmt = stmt.where(Alert.severity == sev)
    if acknowledged is not None:
        stmt = stmt.where(Alert.is_acknowledged.is_(acknowledged))

    total = await db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = (
        (await db.execute(stmt.order_by(Alert.triggered_at.desc()).offset((page - 1) * page_size).limit(page_size)))
        .scalars()
        .all()
    )
    return AlertListResponse(
        items=[_serialize(a) for a in rows],
        total=int(total or 0),
        page=page,
        page_size=page_size,
    )


@router.put("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    _: Annotated[str, Depends(get_current_user)],
) -> dict[str, str]:
    alert = await db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_acknowledged = True
    alert.acknowledged_at = datetime.now(timezone.utc)
    await db.commit()
    return {"status": "ok"}


@router.get("/rules", response_model=list[AlertRuleInfo])
async def alert_rules(
    _: Annotated[str, Depends(get_current_user)],
) -> list[AlertRuleInfo]:
    return [
        AlertRuleInfo(name="BruteForceAlert", description=">10 auth attempts in five minutes", default_severity="HIGH"),
        AlertRuleInfo(name="RCEAttemptAlert", description="RCE classified command or payload observed", default_severity="CRITICAL"),
        AlertRuleInfo(name="NewCountryAlert", description="First time seeing a country in the rolling window", default_severity="LOW"),
        AlertRuleInfo(name="TorExitNodeAlert", description="Source IP present in curated TOR_EXIT_IPS list", default_severity="MEDIUM"),
        AlertRuleInfo(name="CredentialStuffingAlert", description=">30 unique combos in one hour", default_severity="HIGH"),
        AlertRuleInfo(name="AggressiveScannerAlert", description="Burst HTTP traffic or scanner fingerprints", default_severity="MEDIUM"),
        AlertRuleInfo(name="KnownBadIPAlert", description="IP exists in local/community blocklist feed", default_severity="HIGH"),
    ]
