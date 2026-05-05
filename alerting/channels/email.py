"""SMTP email alerting with templated HTML body."""

from __future__ import annotations

import os
from email.message import EmailMessage
from pathlib import Path
import asyncio
import smtplib


class EmailChannel:
    async def send_alert(self, payload: dict[str, object]) -> None:
        enabled = os.getenv("ALERT_EMAIL_ENABLED", "false").lower() == "true"
        if not enabled:
            return

        def _sync_send() -> None:
            frm = os.getenv("ALERT_EMAIL_FROM", "")
            to = os.getenv("ALERT_EMAIL_TO", "")
            host = os.getenv("ALERT_SMTP_HOST", "localhost")
            port = int(os.getenv("ALERT_SMTP_PORT", "587"))
            user = os.getenv("ALERT_SMTP_USER", "")
            password = os.getenv("ALERT_SMTP_PASS", "")
            tls = os.getenv("ALERT_SMTP_TLS", "true").lower() != "false"

            template_path = Path(__file__).resolve().parents[1] / "templates" / "alert_email.html"
            body = template_path.read_text(encoding="utf-8")
            replacements = {
                "{{RULE}}": str(payload.get("rule_name")),
                "{{SEVERITY}}": str(payload.get("severity")),
                "{{DESCRIPTION}}": str(payload.get("description")),
                "{{IP}}": str(payload.get("src_ip")),
                "{{TIME}}": str(payload.get("timestamp")),
                "{{SESSION}}": str(payload.get("session_id")),
            }
            for k, v in replacements.items():
                body = body.replace(k, v)

            msg = EmailMessage()
            msg["Subject"] = f"[{payload.get('severity')}] Honeypot {payload.get('rule_name')}"
            msg["From"] = frm
            msg["To"] = to
            msg.add_alternative(body, subtype="html")

            with smtplib.SMTP(host, port, timeout=30) as smtp:
                if tls:
                    smtp.starttls()
                if user:
                    smtp.login(user, password)
                smtp.send_message(msg)

        await asyncio.to_thread(_sync_send)
