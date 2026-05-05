"""aiohttp-based HTTP honeypot entrypoint."""

from __future__ import annotations

import asyncio
import time

from aiohttp import web

from honeypots.base import BaseHoneypot
from honeypots.config import HoneypotSettings, settings
from honeypots.http import routes
from pipeline.logger import configure_honeypot_logger

_START = time.monotonic()


class HttpHoneypot(BaseHoneypot):
    name = "http"

    def __init__(self, cfg: HoneypotSettings | None = None) -> None:
        super().__init__(cfg or settings())
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    def health_snapshot(self) -> dict[str, object]:
        return {
            "type": "http",
            "status": "up",
            "port": self.cfg.HTTP_HONEYPOT_PORT,
            "sessions_today": int(self.metrics.get("total_sessions_started", 0)),
            "active_sessions": int(self.metrics.get("active_sessions", 0)),
            "uptime_seconds": max(1.0, time.monotonic() - _START),
            "last_event_at": time.monotonic(),
        }

    async def start(self) -> None:
        configure_honeypot_logger("http", "http.jsonl")
        app = web.Application(client_max_size=1024 * 1024)
        app.router.add_route("*", "/login", routes.handle_login)
        app.router.add_route("*", "/admin", routes.handle_admin)
        app.router.add_route("*", "/wp-admin/", routes.handle_wp_admin)
        app.router.add_route("*", "/wp-admin", routes.handle_wp_admin)
        app.router.add_route("*", "/wp-login.php", routes.handle_wp_login)
        app.router.add_route("*", "/phpmyadmin/", routes.handle_phpmyadmin)
        app.router.add_route("*", "/phpmyadmin", routes.handle_phpmyadmin)
        app.router.add_route("*", "/admin/config.php", routes.handle_config_php)
        app.router.add_get("/.env", routes.handle_env)
        app.router.add_get("/etc/passwd", routes.handle_etc_passwd)
        app.router.add_get("/.git/config", routes.handle_git_config)
        app.router.add_route("*", "/api/v1/users", routes.handle_api_users)
        app.router.add_route("*", "/{tail:.*}", routes.fallback)

        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, host="0.0.0.0", port=self.cfg.HTTP_HONEYPOT_PORT)
        await self._site.start()

    async def shutdown(self) -> None:
        if self._site:
            await self._site.stop()
        if self._runner:
            await self._runner.cleanup()


async def main() -> None:
    hp = HttpHoneypot()
    await hp.start()
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
