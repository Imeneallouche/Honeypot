"""Generic webhook POST for alert fan-out."""

from __future__ import annotations

import os
from typing import Mapping

import aiohttp


class WebhookChannel:
    async def send_alert(self, payload: Mapping[str, object]) -> None:
        url = os.getenv("ALERT_WEBHOOK_URL", "").strip()
        if not url:
            return
        headers = {"Content-Type": "application/json"}

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
            async with session.post(url, json=dict(payload), headers=headers) as resp:
                if resp.status >= 400:
                    text = await resp.text()
                    raise RuntimeError(f"Webhook failed {resp.status}: {text}")
