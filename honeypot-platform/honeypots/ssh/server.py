"""AsyncSSH honeypot entrypoint."""

from __future__ import annotations

import asyncio
import time
from threading import Lock
from typing import Any

import asyncssh

from honeypots.base import BaseHoneypot
from honeypots.config import HoneypotSettings, settings
from honeypots.ssh.host_key import ensure_host_key
from honeypots.ssh.session import HoneySSHServer
from pathlib import Path
from pipeline.logger import configure_honeypot_logger

ACTIVE_SESSIONS = 0
_SERVER_START = time.monotonic()
_METRIC_LOCK = Lock()
_LAST_EVENT_MONO = time.monotonic()
_LOGIN_TRACKER: dict[str, int] = {}


def bump_active(delta: int) -> None:
    global ACTIVE_SESSIONS, _LAST_EVENT_MONO
    with _METRIC_LOCK:
        ACTIVE_SESSIONS = max(0, ACTIVE_SESSIONS + delta)
        _LAST_EVENT_MONO = time.monotonic()


class SSHHoneypot(BaseHoneypot):
    name = "ssh"

    def __init__(self, cfg: HoneypotSettings | None = None) -> None:
        super().__init__(cfg or settings())
        self._server_tasks: list[asyncio.Task[None]] = []
        self._listen = None

    def health_snapshot(self) -> dict[str, Any]:
        uptime = max(1.0, time.monotonic() - _SERVER_START)
        sessions_today = int(self.metrics.get("total_sessions_started", 0))
        return {
            "type": "ssh",
            "status": "up",
            "port": self.cfg.SSH_HONEYPOT_PORT,
            "sessions_today": sessions_today,
            "active_sessions": ACTIVE_SESSIONS,
            "uptime_seconds": uptime,
            "last_event_at": _LAST_EVENT_MONO,
        }

    async def start(self) -> None:
        configure_honeypot_logger("ssh", "ssh.jsonl")
        cfg = self.cfg

        root = Path(__file__).resolve().parents[2]
        host_key_target = Path(cfg.SSH_HOST_KEY_PATH).expanduser()
        if not host_key_target.is_absolute():
            host_key_target = root / host_key_target
        key_path = ensure_host_key(host_key_target)

        def factory() -> HoneySSHServer:
            return HoneySSHServer(
                hostname=cfg.SSH_FAKE_HOSTNAME,
                login_tracker=_LOGIN_TRACKER,
                tarpit_threshold=cfg.TARPIT_THRESHOLD,
                tarpit_delay_ms=cfg.TARPIT_DELAY_MS,
                adjust_active=bump_active,
            )

        self._listen = await asyncssh.listen(
            "",
            cfg.SSH_HONEYPOT_PORT,
            server_factory=factory,
            server_host_keys=[key_path],
        )

        async def _uptime_ticker() -> None:
            while True:
                await asyncio.sleep(5)
                with self.metrics_lock:
                    self.metrics["uptime_ticks"] = int(time.monotonic() - _SERVER_START)

        self._server_tasks.append(asyncio.create_task(_uptime_ticker()))

    async def shutdown(self) -> None:
        for task in self._server_tasks:
            task.cancel()
        if self._listen:
            self._listen.close()
            await self._listen.wait_closed()


async def main() -> None:
    hp = SSHHoneypot()
    await hp.start()
    try:
        await asyncio.Future()
    except asyncio.CancelledError:
        await hp.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
