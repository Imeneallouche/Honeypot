"""Slack incoming webhook transport."""

from __future__ import annotations

import json
import os
import aiohttp


class SlackChannel:
    async def send_alert(self, payload: dict[str, object]) -> None:
        webhook = os.getenv("ALERT_SLACK_WEBHOOK_URL", "").strip()
        if not webhook:
            return

        attachment = {
            "color": "#ff4444" if str(payload.get("severity")) == "CRITICAL" else "#00d4ff",
            "fallback": json.dumps(payload, default=str),
            "fields": [
                {"title": k, "value": str(v), "short": True}
                for k, v in payload.items()
                if k in {"severity", "src_ip", "rule_name"}
            ]
            + [
                {"title": "detail", "value": str(payload.get("description", ""))[:2000], "short": False},
            ],
        }

        slack_body = {"text": f"*Honeypot Alert* `{payload.get('rule_name')}`", "attachments": [attachment]}

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
            async with session.post(webhook, json=slack_body) as resp:
                if resp.status >= 400:
                    text = await resp.text()
                    raise RuntimeError(f"Slack webhook failed {resp.status}: {text}")
