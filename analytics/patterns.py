"""Threat-pattern heuristics (used by alerting and smoke tests)."""

from __future__ import annotations


def detect_brute_force(attempt_counts: dict[str, int], threshold: int = 10) -> bool:
    """Return True when any fingerprint exceeds brute-force heuristic."""
    if not attempt_counts:
        return False
    return max(attempt_counts.values()) >= threshold
