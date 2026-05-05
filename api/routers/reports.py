"""Threat-report lifecycle (JSON+PDF bundles)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from analytics import reporter
from api.dependencies import get_current_user, get_db_session
from api.schemas import ReportGenerateRequest, ReportGenerateResponse, ReportListItem, ReportListResponse
from pipeline.models import ThreatReport

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/generate", response_model=ReportGenerateResponse)
async def generate_report(
    body: ReportGenerateRequest,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    _: Annotated[str, Depends(get_current_user)],
) -> ReportGenerateResponse:
    record = await reporter.generate_json_report(db, body.period_days)
    await db.commit()
    return ReportGenerateResponse(report_id=record.id, message="Report materialized")


@router.get("", response_model=ReportListResponse)
async def list_reports(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    _: Annotated[str, Depends(get_current_user)],
) -> ReportListResponse:
    rows = (await db.execute(select(ThreatReport).order_by(ThreatReport.generated_at.desc()).limit(50))).scalars().all()
    items = [
        ReportListItem(
            id=r.id,
            generated_at=r.generated_at,
            period_start=r.period_start,
            period_end=r.period_end,
            report_type=r.report_type.value,
            json_path=r.json_path,
            pdf_path=r.pdf_path,
            summary_stats=r.summary_stats if isinstance(r.summary_stats, dict) else None,
        )
        for r in rows
    ]
    return ReportListResponse(items=items)


@router.get("/{report_id}/download")
async def download_report(
    report_id: int,
    db: Annotated[AsyncSession, Depends(get_db_session)],
    _: Annotated[str, Depends(get_current_user)],
) -> FileResponse:
    row = await db.get(ThreatReport, report_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Report not found")

    path = Path(row.pdf_path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="PDF artifact missing on disk")
    return FileResponse(path, filename=path.name, media_type="application/pdf")
