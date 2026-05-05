"""GeoIP2 (MaxMind Lite) lookup → country, city, ASN metadata."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import geoip2.database
    import geoip2.errors
except ImportError:
    geoip2 = None


@dataclass
class GeoResult:
    country: Optional[str]
    city: Optional[str]
    asn: Optional[int]
    isp: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]


class GeoIpService:
    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(
            db_path or os.getenv("GEOIP_DB_PATH", "./data/GeoLite2-City.mmdb")
        ).expanduser()
        self._reader_city = None
        self._reader_asn = None
        if geoip2 and self.db_path.is_file():
            try:
                self._reader_city = geoip2.database.Reader(str(self.db_path))
            except OSError:
                self._reader_city = None
        asn_path = self.db_path.parent / "GeoLite2-ASN.mmdb"
        if geoip2 and asn_path.is_file():
            try:
                self._reader_asn = geoip2.database.Reader(str(asn_path))
            except OSError:
                self._reader_asn = None

    def close(self) -> None:
        if self._reader_city:
            self._reader_city.close()
        if self._reader_asn:
            self._reader_asn.close()

    def lookup(self, ip_str: str) -> GeoResult:
        if not self._reader_city:
            return GeoResult(None, None, None, None, None, None)
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                return GeoResult("Private", None, None, None, None, None)
        except ValueError:
            return GeoResult(None, None, None, None, None, None)

        try:
            rec = self._reader_city.city(ip_str)
        except geoip2.errors.AddressNotFoundError:
            return GeoResult(None, None, None, None, None, None)
        except Exception:
            return GeoResult(None, None, None, None, None, None)

        country = rec.country.iso_code or rec.country.name
        city = rec.city.name
        lat = rec.location.latitude
        lon = rec.location.longitude

        asn_val: Optional[int] = None
        isp: Optional[str] = None
        if self._reader_asn:
            try:
                arec = self._reader_asn.asn(ip_str)
                asn_val = int(arec.autonomous_system_number)
                isp = arec.autonomous_system_organization
            except Exception:
                pass

        return GeoResult(country=country, city=city, asn=asn_val, isp=isp, latitude=lat, longitude=lon)
