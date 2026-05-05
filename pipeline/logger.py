"""Structured JSON logger (used by all honeypots)."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger

_LOG_DIR: Path | None = None


def _root_dir() -> Path:
    return Path(__file__).resolve().parents[1]


def configure_honeypot_logger(service_name: str, log_filename: str | None = None) -> Path:
    """
    Configure loguru: JSON lines to ./logs/<service>.jsonl with rotation,
    and human-readable warnings to stderr.
    """
    global _LOG_DIR
    logger.remove()

    log_dir = Path(os.getenv("LOG_DIR", str(_root_dir() / "logs")))
    log_dir.mkdir(parents=True, exist_ok=True)
    _LOG_DIR = log_dir
    filepath = log_dir / (log_filename or f"{service_name}.jsonl")

    logger.add(
        filepath,
        rotation="50 MB",
        retention="14 days",
        compression="gz",
        level="INFO",
        format="{message}",
        encoding="utf-8",
    )
    logger.add(
        sys.stderr,
        level="WARNING",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}",
        colorize=True,
    )
    print(f"[honeypot:{service_name}] JSON logs -> {filepath}", file=sys.stderr)
    return filepath.resolve()


def emit(event: dict[str, Any]) -> None:
    """Append a structured JSON record (one log line == one JSON object)."""
    enriched = dict(event)
    enriched.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    logger.info(json.dumps(enriched, default=str))


def emit_batch(events: list[dict[str, Any]]) -> None:
    for evt in events:
        emit(evt)
