"""Abstract honeypot base class."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from threading import Lock
from typing import Any

from honeypots.config import HoneypotSettings


class BaseHoneypot(ABC):
    name: str = "base"
    metrics_lock: Lock = Lock()
    metrics: dict[str, Any]

    def __init__(self, cfg: HoneypotSettings | None = None) -> None:
        self.cfg = cfg or HoneypotSettings()
        self.metrics = {
            "active_sessions": 0,
            "total_sessions_started": 0,
            "uptime_ticks": 0,
        }

    def bump_sessions(self, delta: int) -> None:
        with self.metrics_lock:
            self.metrics["active_sessions"] = max(
                0, int(self.metrics.get("active_sessions", 0)) + delta
            )
            if delta > 0:
                self.metrics["total_sessions_started"] = int(
                    self.metrics.get("total_sessions_started", 0)
                ) + 1

    @abstractmethod
    async def start(self) -> None:
        """Run the honeypot until cancelled."""

    @abstractmethod
    async def shutdown(self) -> None:
        """Graceful teardown."""

    @abstractmethod
    def health_snapshot(self) -> dict[str, Any]:
        """Return telemetry for API health endpoint."""
