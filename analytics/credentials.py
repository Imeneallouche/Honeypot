"""Credential analytics helpers."""

from __future__ import annotations

from typing import Iterable


def top_usernames(pairs: Iterable[tuple[str, str]], *, limit: int = 10) -> list[tuple[str, int]]:
    """Aggregate username occurrences from (username, password) tuples."""
    counts: dict[str, int] = {}
    for user, _ in pairs:
        u = user.strip() or "(empty)"
        counts[u] = counts.get(u, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    return ranked[:limit]
