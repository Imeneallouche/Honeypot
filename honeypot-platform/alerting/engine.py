"""Alert orchestration (ingestion + periodic sweeps)."""

from __future__ import annotations

from typing import Any

from loguru import logger

from pipeline.database import get_session_factory


class AlertEngine:
    """Placeholder facade for tooling / backwards compatibility."""

    async def evaluate(self, payload: dict[str, Any]) -> None:
        factory = get_session_factory()
        async with factory() as db:
            from alerting.rules import RULES

            for rule in RULES:
                await rule.evaluate(db, payload)


async def evaluate_ingestion_batch(events: list[dict[str, Any]]) -> None:
    if not events:
        return

    from alerting.rules import RULES

    factory = get_session_factory()
    async with factory() as db:
        for evt in events:
            for rule in RULES:
                try:
                    await rule.evaluate(db, evt)
                except Exception as exc:  # pragma: no cover - safety net
                    logger.exception("rule {} failed {}", getattr(rule, "name", "?"), exc)
        await db.commit()


async def evaluate_periodic_signals() -> None:
    """Hook for cron-style rules; SQLite workload kept light by default."""
    logger.debug("periodic alerting sweep noop")
