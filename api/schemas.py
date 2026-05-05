"""Pydantic schemas for the public REST API surface."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ORMBase(BaseModel):
    """Models built from SQLAlchemy rows / query results."""

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = Field(default="bearer")


class RefreshRequest(BaseModel):
    refresh_token: str


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"


class HourlyCount(BaseModel):
    hour: str
    count: int


class OverviewStatsResponse(BaseModel):
    total_sessions_24h: int
    total_sessions_7d: int
    total_sessions_30d: int
    unique_ips_24h: int
    top_country: str | None
    top_username: str | None
    top_password: str | None
    active_sessions_now: int
    alerts_unacknowledged: int
    attack_types_breakdown: dict[str, int]
    sessions_per_hour_last_24h: list[HourlyCount]


class LiveTickerStat(BaseModel):
    events_last_60s: int
    unique_ips_last_60s: int
    newest_event_at: datetime | None


class SessionListItem(ORMBase):
    id: int
    honeypot_type: str
    src_ip: str
    src_port: int | None
    country: str | None
    city: str | None
    started_at: datetime
    ended_at: datetime | None
    duration_seconds: float | None
    threat_score: int
    is_acknowledged: bool
    commands_count: int
    http_requests_count: int


class SessionListResponse(BaseModel):
    items: list[SessionListItem]
    total: int
    page: int
    page_size: int


class AuthAttemptOut(ORMBase):
    id: int
    username: str
    password: str
    attempt_number: int
    timestamp: datetime
    success: bool


class ShellCommandOut(ORMBase):
    id: int
    command: str
    arguments: str | None
    timestamp: datetime
    is_malicious: bool
    malicious_category: str | None


class HttpRequestOut(ORMBase):
    id: int
    method: str
    path: str
    query_string: str | None
    body: str | None
    user_agent: str | None
    attack_type: str
    is_scanner: bool
    scanner_tool: str | None
    timestamp: datetime
    response_code: int


class PayloadOut(ORMBase):
    id: int
    raw_payload: str
    payload_type: str
    decoded_payload: str | None
    extracted_urls: list[str] | None
    extracted_ips: list[str] | None
    severity: str


class SessionDetailResponse(BaseModel):
    session: SessionListItem
    auth_attempts: list[AuthAttemptOut]
    shell_commands: list[ShellCommandOut]
    http_requests: list[HttpRequestOut]
    payloads: list[PayloadOut]
    latitude: float | None
    longitude: float | None


class TopIpRow(BaseModel):
    ip: str
    count: int
    country: str | None
    flag: str
    threat_score: int
    last_seen: datetime


class TopCountryRow(BaseModel):
    country: str
    count: int
    flag: str
    percentage: float


class AttackerProfileResponse(BaseModel):
    ip: str
    sessions: list[SessionListItem]
    commands: list[ShellCommandOut]
    credentials: list[AuthAttemptOut]
    payloads: list[PayloadOut]
    threat_score_latest: int


class PayloadListItem(ORMBase):
    id: int
    session_id: int
    src_ip: str
    payload_type: str
    severity: str
    raw_payload: str
    decoded_payload: str | None
    timestamp: datetime


class PayloadListResponse(BaseModel):
    items: list[PayloadListItem]
    total: int
    page: int
    page_size: int


class PayloadStatsResponse(BaseModel):
    by_type: dict[str, int]
    by_severity: dict[str, int]


class RankedString(BaseModel):
    value: str
    count: int


class CredentialComboRow(BaseModel):
    username: str
    password: str
    count: int


class AlertItem(ORMBase):
    id: int
    rule_name: str
    severity: str
    description: str
    src_ip: str
    session_id: int | None
    triggered_at: datetime
    is_acknowledged: bool
    acknowledged_at: datetime | None


class AlertListResponse(BaseModel):
    items: list[AlertItem]
    total: int
    page: int
    page_size: int


class AlertRuleInfo(BaseModel):
    name: str
    description: str
    default_severity: str


class ReportGenerateRequest(BaseModel):
    period_days: int = Field(default=7, ge=1, le=365)


class ReportGenerateResponse(BaseModel):
    report_id: int
    message: str


class ReportListItem(ORMBase):
    id: int
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    report_type: str
    json_path: str
    pdf_path: str
    summary_stats: dict[str, int | float | str] | None


class ReportListResponse(BaseModel):
    items: list[ReportListItem]


class HoneypotStatusRow(BaseModel):
    type: str
    status: str
    port: int
    sessions_today: int
    uptime_seconds: float
    last_event_at: datetime | None
