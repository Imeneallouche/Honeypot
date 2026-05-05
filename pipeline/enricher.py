"""Enrich events with GeoIP, reverse DNS hints, and lightweight threat signals."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any

from pipeline.geoip import GeoIpServiceclass EventEnricher:
    def __init__(self, geo: GeoIpService | None = None) -> None:
        self.geo = geo or GeoIpService()

    async def reverse_dns(self, ip: str) -> str | None:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None

        def _lookup() -> str | None:
            try:
                return socket.gethostbyaddr(ip)[0]
            except OSError:
                return None

        return await asyncio.to_thread(_lookup)

    async def enrich_ip(self, ip: str, payload: dict[str, Any]) -> dict[str, Any]:
        geo = await asyncio.to_thread(self.geo.lookup, ip)
        out = dict(payload)
        out.setdefault("geo", {})
        out["geo"].update(
            {
                "country": geo.country,
                "city": geo.city,
                "asn": geo.asn,
                "isp": geo.isp,
                "latitude": geo.latitude,
                "longitude": geo.longitude,
            }
        )
        ptr = await self.reverse_dns(ip)
        if ptr:
            out["reverse_dns"] = ptr
        out["is_tor"] = await self._is_likely_tor_exit(ip)
        out["is_vpn"] = False
        return out

    async def _is_likely_tor_exit(self, ip: str) -> bool:
        """Heuristic: check local cache file or optional future list fetch; default false."""
        # Without persisting bulk lists in-image, avoid network on every event.
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False
        return False


def heuristic_threat_boost(event: dict[str, Any]) -> int:
    """Return 0–40 score bump from simple signals (not full analytics)."""
    score = 0
    et = str(event.get("attack_type", "")).lower()
    if et in {"rce", "lfi", "rfi", "ssrf"}:
        score += 15
    if event.get("is_scanner"):
        score += 8
    if event.get("geo", {}).get("country") == "Private":
        score += 5
    return min(score, 40)
