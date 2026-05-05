"""Route alerts to enabled notification channels."""

from __future__ import annotations

import asyncio
import os
from typing import Any

from loguru import logger

from pipeline.models import Alert, AlertSeverity

from alerting.channels.email import EmailChannel
from alerting.channels.slack import SlackChannel
from alerting.channels.webhook import WebhookChannel

_CHANNEL_CACHE: dict[str, Any] = {}


def _rank(sev: AlertSeverity) -> int:
    key = sev.value.upper()
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[key]


def min_severity_for_channel(channel: str) -> AlertSeverity:
    env_key = channel.upper()
    mapping = os.getenv(f"ALERT_MIN_SEVERITY_{env_key}", "").upper()
    if mapping == "LOW":
        return AlertSeverity.low
    if mapping == "MEDIUM":
        return AlertSeverity.medium
    if mapping == "HIGH":
        return AlertSeverity.high
    if mapping == "CRITICAL":
        return AlertSeverity.critical
    if env_key == "WEBHOOK":
        return AlertSeverity.low
    if env_key == "SLACK":
        return AlertSeverity.medium
    return AlertSeverity.high


def _allowed(severity: AlertSeverity, minimum: AlertSeverity) -> bool:
    return _rank(severity) >= _rank(minimum)


async def notify_alert(alert: Alert) -> None:
    payload = {
        "rule_name": alert.rule_name,
        "severity": alert.severity.value,
        "description": alert.description,
        "src_ip": alert.src_ip,
        "timestamp": alert.triggered_at.isoformat(),
        "session_id": alert.session_id,
    }

    tasks: list[asyncio.Task[None]] = []

    if os.getenv("ALERT_EMAIL_ENABLED", "false").lower() == "true":
        if _allowed(alert.severity, min_severity_for_channel("EMAIL")):
            emailer = _CHANNEL_CACHE.setdefault("email", EmailChannel())
            tasks.append(asyncio.create_task(emailer.send_alert(payload)))

    if os.getenv("ALERT_SLACK_ENABLED", "false").lower() == "true":
        if _allowed(alert.severity, min_severity_for_channel("SLACK")):
            slack = _CHANNEL_CACHE.setdefault("slack", SlackChannel())
            tasks.append(asyncio.create_task(slack.send_alert(payload)))

    if os.getenv("ALERT_WEBHOOK_ENABLED", "false").lower() == "true":
        if _allowed(alert.severity, min_severity_for_channel("WEBHOOK")):
            hook = _CHANNEL_CACHE.setdefault("webhook", WebhookChannel())
            tasks.append(asyncio.create_task(hook.send_alert(payload)))

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, Exception):
                logger.error("notification dispatch failed {}", res)
