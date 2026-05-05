"""SQLAlchemy 2.0 async models for honeypot telemetry."""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class HoneypotType(str, enum.Enum):
    ssh = "ssh"
    http = "http"


class Severity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ReportType(str, enum.Enum):
    summary = "summary"
    executive = "executive"
    technical = "technical"


class HoneypotSession(Base):
    __tablename__ = "honeypot_sessions"
    __table_args__ = (
        UniqueConstraint(
            "honeypot_type",
            "external_session_id",
            name="uq_honeypot_external_session",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    honeypot_type: Mapped[HoneypotType] = mapped_column(
        Enum(HoneypotType, name="honeypot_type"), index=True
    )
    external_session_id: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    asn: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    isp: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    latitude: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    longitude: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ended_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    is_tor: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    is_vpn: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    threat_score: Mapped[int] = mapped_column(Integer, default=0)
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")

    auth_attempts: Mapped[list["AuthAttempt"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    shell_commands: Mapped[list["ShellCommand"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    http_requests: Mapped[list["HttpRequest"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    payloads: Mapped[list["Payload"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        foreign_keys="Alert.session_id",
    )


class AuthAttempt(Base):
    __tablename__ = "auth_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("honeypot_sessions.id", ondelete="CASCADE"))
    username: Mapped[str] = mapped_column(String(512))
    password: Mapped[str] = mapped_column(String(512))
    attempt_number: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    success: Mapped[bool] = mapped_column(Boolean, default=False)

    session: Mapped["HoneypotSession"] = relationship(back_populates="auth_attempts")


class ShellCommand(Base):
    __tablename__ = "shell_commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("honeypot_sessions.id", ondelete="CASCADE"))
    command: Mapped[str] = mapped_column(Text)
    arguments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False)
    malicious_category: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    session: Mapped["HoneypotSession"] = relationship(back_populates="shell_commands")


class HttpRequest(Base):
    __tablename__ = "http_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("honeypot_sessions.id", ondelete="CASCADE"))
    method: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(Text)
    query_string: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    attack_type: Mapped[str] = mapped_column(String(64))
    is_scanner: Mapped[bool] = mapped_column(Boolean, default=False)
    scanner_tool: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    response_code: Mapped[int] = mapped_column(Integer)

    session: Mapped["HoneypotSession"] = relationship(back_populates="http_requests")


class Payload(Base):
    __tablename__ = "payloads"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("honeypot_sessions.id", ondelete="CASCADE"))
    raw_payload: Mapped[str] = mapped_column(Text)
    payload_type: Mapped[str] = mapped_column(String(64), index=True)
    decoded_payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    extracted_urls: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    extracted_ips: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    severity: Mapped[str] = mapped_column(String(32))

    session: Mapped["HoneypotSession"] = relationship(back_populates="payloads")


class AlertSeverity(str, enum.Enum):
    low = "LOW"
    medium = "MEDIUM"
    high = "HIGH"
    critical = "CRITICAL"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_name: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, name="alert_severity"), index=True
    )
    description: Mapped[str] = mapped_column(Text)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    session_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("honeypot_sessions.id", ondelete="SET NULL"), nullable=True
    )
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    dedupe_key: Mapped[Optional[str]] = mapped_column(String(256), unique=True, nullable=True)

    session: Mapped[Optional["HoneypotSession"]] = relationship(
        back_populates="alerts",
        foreign_keys=[session_id],
    )


class ThreatReport(Base):
    __tablename__ = "threat_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    report_type: Mapped[ReportType] = mapped_column(Enum(ReportType, name="report_type"))
    json_path: Mapped[str] = mapped_column(String(512))
    pdf_path: Mapped[str] = mapped_column(String(512))
    summary_stats: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)


class FeedEvent(Base):
    """Real-time websocket feed rows (normalized from ingest pipeline)."""

    __tablename__ = "feed_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(Text)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    country: Mapped[Optional[str]] = mapped_column(String(128))
    honeypot_type: Mapped[str] = mapped_column(String(16))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class SeenCountry(Base):
    """Tracks first-seen dates for alerting (New Country rule)."""

    __tablename__ = "seen_countries"
    __table_args__ = (UniqueConstraint("country_code", name="uq_seen_country_code"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    country_code: Mapped[str] = mapped_column(String(4), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class DedupeFingerprint(Base):
    """Alert deduplication fingerprints (expire after one hour logically in app layer)."""

    __tablename__ = "alert_dedupe"

    key: Mapped[str] = mapped_column(String(512), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
