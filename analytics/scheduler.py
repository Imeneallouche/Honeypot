"""APScheduler-compatible asyncio loop invoking analytics/engine."""

from __future__ import annotations

import asyncio
import os

from loguru import logger

from analytics.engine import run_analytics_cycle


async def _runner() -> None:
    minutes = float(os.getenv("ANALYTICS_INTERVAL_MINUTES", "5"))
    delay = max(1.0, minutes * 60.0)
    logger.warning("analytics scheduler armed interval=%sm", minutes)
    while True:
        try:
            await run_analytics_cycle()
        except Exception as exc:
            logger.exception("scheduler tick failed {}", exc)
        await asyncio.sleep(delay)


def main() -> None:
    asyncio.run(_runner())


if __name__ == "__main__":
    main()
