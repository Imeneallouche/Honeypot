"""Payload taxonomy and heuristic classification helpers."""

from __future__ import annotations

import base64
import binascii
import enum
import re
import urllib.parse
from ipaddress import ip_address as parse_ip_address
from typing import Iterable

_SQLI_PATTERN = re.compile(
    r"(union\s+select|or\s+\d\s*=\s*\d|'?\s+or\s+1\s*=\s*1|drop\s+table|sleep\s*\(|benchmark\s*\(|information_schema|'--|%27--)",
    re.IGNORECASE,
)
_XSS_PATTERN = re.compile(
    r"(<script|onerror\s*=|<iframe|javascript:|vbscript:|%3cscript|onmouseover\s*=)",
    re.IGNORECASE,
)
_LFI_PATTERN = re.compile(
    r"(/etc/passwd|/etc/shadow|%2fetc%2fpasswd|%00|php://filter|glob://)",
    re.IGNORECASE,
)
_RFI_PATTERN = re.compile(
    r"(https?://[^\"'\s]+/(shell|cgi-bin|evil)|php://input|expect://)",
    re.IGNORECASE,
)
_PATH_TRAVERSAL_PATTERN = re.compile(
    r"(\.\./|\.\.%2f|%252e%252e%252f|%252e%252e%255c|%2e%2e%2f|%2e%2e%5c)",
    re.IGNORECASE,
)
_RCE_PATTERN = re.compile(
    r"(;\s*\w+|&&|\|\|\s*|`[^`\n]{1,}|>\s*\${|wget\s+http|\bcurl\s+\S+|chmod\s+[0-7]{3}|/bin/busybox|`id`|\$\(wget|\$\{IFS\})",
    re.IGNORECASE,
)
_SSFR_PATTERN = re.compile(
    r"(169\.254\.169\.254|metadata\.google|localhost|127\.0\.0\.1|192\.168\.\d{1,3}|10\.\d{1,3}\.\d{1,3})",
)


class PayloadType(str, enum.Enum):
    benign = "benign"
    sql_injection = "sql_injection"
    xss = "xss"
    lfi = "lfi"
    rfi = "rfi"
    rce = "rce"
    ssrf = "ssrf"
    path_traversal = "path_traversal"
    credential_probe = "credential_probe"
    info_disclosure = "info_disclosure"
    scanner_probe = "scanner_probe"


def classify_payload(raw: str) -> PayloadType:
    if not raw:
        return PayloadType.benign
    snippet = urllib.parse.unquote_plus(raw.lower())
    detectors: Iterable[tuple[PayloadType, re.Pattern[str]]] = (
        (PayloadType.sql_injection, _SQLI_PATTERN),
        (PayloadType.xss, _XSS_PATTERN),
        (PayloadType.lfi, _LFI_PATTERN),
        (PayloadType.rfi, _RFI_PATTERN),
        (PayloadType.path_traversal, _PATH_TRAVERSAL_PATTERN),
        (PayloadType.rce, _RCE_PATTERN),
        (PayloadType.ssrf, _SSFR_PATTERN),
    )
    for ptype, pat in detectors:
        if pat.search(snippet):
            return ptype
    if re.search(r"(admin|ftp|oracle|smtp|credential|smtp_pass|password\b)", snippet):
        return PayloadType.credential_probe
    ua_snippet = snippet
    scanner_markers = (
        "nikto",
        "sqlmap",
        "masscan",
        "nuclei",
        "zgrab",
        "shodan",
        "censys",
        "burp-collaborator",
        "wpscan",
    )
    for marker in scanner_markers:
        if marker in ua_snippet:
            return PayloadType.scanner_probe

    disclosure_markers = (".git/config", "/.env", "phpmyadmin/scripts")
    if any(m in ua_snippet for m in disclosure_markers):
        return PayloadType.info_disclosure

    return PayloadType.benign


def extract_urls(payload: str) -> list[str]:
    return re.findall(r"https?://[^\s\"\']+", payload)


def extract_ips(payload: str) -> list[str]:
    ips: list[str] = []
    ipv4_pat = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )
    cand = ipv4_pat.findall(payload)
    for c in cand:
        try:
            parse_ip_address(c)
            ips.append(c)
        except ValueError:
            continue
    return ips


def decode_payload(payload: str) -> str | None:
    candidates: list[str] = []

    decoded_url = urllib.parse.unquote(payload)
    if decoded_url != payload:
        candidates.append(decoded_url)

    compact = payload.strip()
    if compact:
        padd = "=" * (-len(compact) % 4)
        try:
            b = base64.b64decode(compact + padd, validate=False)
            decoded_bytes = b.decode(errors="ignore")
            if decoded_bytes and decoded_bytes != payload:
                candidates.append(decoded_bytes)
        except (binascii.Error, ValueError, UnicodeDecodeError):
            pass

    if re.search(r"\\x[a-fA-F0-9]{2}", payload.lower()):
        try:
            stripped = bytes(
                int(hex_pair, 16)
                for hex_pair in re.findall(r"\\x([a-fA-F0-9]{2})", payload.lower())
            ).decode(errors="ignore")
            if stripped and stripped != payload:
                candidates.append(stripped)
        except ValueError:
            pass

    if not candidates:
        return None

    best = sorted(set(candidates), key=len)[-1]
    return None if best == payload else best
