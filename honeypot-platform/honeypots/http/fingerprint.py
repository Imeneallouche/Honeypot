"""HTTP fingerprinting utilities."""

from __future__ import annotations

import re
from typing import Any

from analytics.payloads import PayloadType, classify_payload

SCANNER_UA = {
    "sqlmap": "sqlmap",
    "nikto": "nikto",
    "nmap": "nmap scripting engine",
    "masscan": "masscan",
    "nuclei": "nuclei",
    "burp": "burp",
    "zap": "zaproxy",
    "shodan": "shodan",
    "censys": "censys",
}


def classify_attack(request_path: str, body: str) -> PayloadType:
    combined = f"{request_path}\n{body}"
    return classify_payload(combined)


def classify_scanner(headers: dict[str, str]) -> tuple[bool, str | None]:
    ua = ""
    if headers:
        for key, value in headers.items():
            if key.lower() == "user-agent":
                ua = value.lower()
                break
        if not ua and "User-Agent" in headers:
            ua = headers.get("User-Agent", "").lower()
    if not ua:
        return False, None
    for name, needle in SCANNER_UA.items():
        if needle in ua:
            return True, name
    return False, None


def extract_headers(multi: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if multi is None:
        return out
    try:
        for key in multi.keys():
            val = ",".join(multi.getall(key)) if hasattr(multi, "getall") else str(multi[key])
            out[str(key)] = val
    except Exception:
        return out
    return out


_PATTERN_MARKERS = {
    PayloadType.scanner_probe: re.compile(r"(\bwget\b|curl|%00|etc/passwd|phpmyadmin)", re.I),
}


def refine_attack_type(base: PayloadType, path: str, body: str) -> str:
    if base != PayloadType.benign:
        return base.value
    combined = f"{path} {body}".lower()
    if "wp-admin" in path or "/xmlrpc.php" in path:
        return "scanner_probe"
    if ".." in combined or "..%2f" in combined or "%252e" in combined:
        return PayloadType.path_traversal.value
    if "benchmark(" in combined or "sleep(" in combined:
        return PayloadType.sql_injection.value
    if "=" in combined and "'" in combined and "union" not in combined and "sleep" not in combined:
        return PayloadType.sql_injection.value
    return PayloadType.benign.value
