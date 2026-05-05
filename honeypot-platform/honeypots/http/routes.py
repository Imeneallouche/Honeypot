"""HTTP route handlers for deception pages."""

from __future__ import annotations

import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic

import json

from aiohttp import web

from honeypots.http.fingerprint import classify_attack, classify_scanner, extract_headers, refine_attack_type
from pipeline.logger import emit

_HIT_WINDOW = 60.0
_HIT_LIMIT = 20
_REQUEST_LOG: defaultdict[str, deque[float]] = defaultdict(deque)


def _rate_state(ip: str) -> tuple[int, bool]:
    now = monotonic()
    dq = _REQUEST_LOG[ip]
    while dq and dq[0] < now - _HIT_WINDOW:
        dq.popleft()
    count = len(dq)
    aggressive = count >= _HIT_LIMIT
    dq.append(now)
    return count, aggressive


def _peer(req: web.Request) -> tuple[str, int]:
    fwd = req.headers.get("X-Forwarded-For")
    ip = fwd.split(",")[0].strip() if fwd else (req.transport.get_extra_info("peername")[0] if req.transport else None) or req.remote or "127.0.0.1"
    try:
        port = int(req.transport.get_extra_info("peername")[1])
    except Exception:
        port = 0
    return str(ip), port


async def _read_body(req: web.Request, limit: int = 8192) -> str:
    try:
        payload = await req.read()
        decoded = payload.decode(errors="ignore")
        return decoded[:limit]
    except Exception:
        return ""


def _ensure_session(app: web.Application, ip: str) -> str:
    store: dict[str, str] = app.setdefault("hp_tcp_sessions", {})
    if ip not in store:
        store[ip] = str(uuid.uuid4())
    return store[ip]


async def _render(req: web.Request, name: str, context: dict[str, str] | None = None) -> web.Response:
    ctx = context or {}
    folder = Path(__file__).parent / "templates"
    text = (folder / name).read_text(encoding="utf-8")
    for k, v in ctx.items():
        text = text.replace(f"{{{{{k}}}}}", v)
    return web.Response(text=text, content_type="text/html", charset="utf-8")


def _apache_headers() -> dict[str, str]:
    return {
        "Server": "Apache/2.4.52 (Ubuntu) OpenSSL/1.1.1f",
        "X-Powered-By": "PHP/8.1.2",
    }


def _attach_headers(resp: web.Response) -> web.Response:
    for k, v in _apache_headers().items():
        resp.headers.setdefault(k, v)
    return resp


async def _log_request(
    req: web.Request,
    *,
    status: int,
    body: str,
    attack_type: str,
    is_scanner: bool,
    scanner_tool: str | None,
    aggressive: bool,
) -> None:
    ip, port = _peer(req)
    session_id = _ensure_session(req.app, ip)
    headers = extract_headers(req.headers)
    emit(
        {
            "event": "http_request",
            "honeypot": "http",
            "session_id": session_id,
            "src_ip": ip,
            "src_port": port,
            "method": req.method,
            "path": req.path,
            "query_string": req.query_string if req.query_string else None,
            "body": body,
            "headers": headers,
            "user_agent": headers.get("User-Agent") or headers.get("user-agent"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": attack_type,
            "is_scanner": is_scanner,
            "scanner_tool": scanner_tool,
            "response_code": status,
            "aggressive_scanner": aggressive or bool(is_scanner and attack_type != "benign"),
        }
    )


async def handle_login(req: web.Request) -> web.Response:
    ip, _ = _peer(req)
    _, aggressive = _rate_state(ip)
    headers = extract_headers(req.headers)
    scanner, scanner_tool = classify_scanner(headers)
    body = await _read_body(req)
    attack = classify_attack(f"{req.method} {req.path_qs}\n{body}", body)
    atk = refine_attack_type(attack, req.path_qs + body, body)

    if req.method.upper() == "POST":
        await _log_request(
            req,
            status=302,
            body=body,
            attack_type="credential_stuffing",
            is_scanner=scanner,
            scanner_tool=scanner_tool,
            aggressive=True,
        )
        resp = web.Response(status=302)
        resp.headers["Location"] = "/admin"
        return _attach_headers(resp)

    resp = await _render(req, "login.html")
    await _log_request(
        req,
        status=200,
        body=body,
        attack_type=str(atk),
        is_scanner=scanner,
        scanner_tool=scanner_tool,
        aggressive=aggressive,
    )
    return _attach_headers(resp)


async def handle_admin(req: web.Request) -> web.Response:
    ip, _ = _peer(req)
    _, aggressive = _rate_state(ip)
    headers = extract_headers(req.headers)
    scanner, scanner_tool = classify_scanner(headers)
    body = await _read_body(req)
    attack = classify_attack(req.path_qs + body, body)
    atk = refine_attack_type(attack, req.path_qs + body, body)
    resp = await _render(req, "admin.html")
    await _log_request(
        req,
        status=200,
        body=body,
        attack_type=str(atk),
        is_scanner=scanner,
        scanner_tool=scanner_tool,
        aggressive=aggressive,
    )
    return _attach_headers(resp)


async def handle_wp_admin(req: web.Request) -> web.Response:
    ip, _ = _peer(req)
    _, aggressive = _rate_state(ip)
    headers = extract_headers(req.headers)
    scanner, scanner_tool = classify_scanner(headers)
    body = await _read_body(req)
    attack = classify_attack(req.path_qs + body, body)
    atk = refine_attack_type(attack, req.path_qs + body, body)
    html = """
    <html><head><title>WordPress &rsaquo; Login</title></head>
    <body><h1>wp-admin</h1><form method='post'><input name='log' placeholder='user'>
    <input name='pwd' type='password' placeholder='pass'><button>Login</button></form></body></html>
    """
    resp = web.Response(text=html, content_type="text/html")
    await _log_request(
        req,
        status=200,
        body=body,
        attack_type=str(atk),
        is_scanner=scanner,
        scanner_tool=scanner_tool,
        aggressive=aggressive,
    )
    return _attach_headers(resp)


async def handle_wp_login(req: web.Request) -> web.Response:
    return await handle_wp_admin(req)


async def handle_phpmyadmin(req: web.Request) -> web.Response:
    ip, _ = _peer(req)
    _, aggressive = _rate_state(ip)
    headers = extract_headers(req.headers)
    scanner, scanner_tool = classify_scanner(headers)
    body = await _read_body(req)
    attack = classify_attack(req.path_qs + body, body)
    atk = refine_attack_type(attack, req.path_qs + body, body)
    html = "<html><body><h1>phpMyAdmin</h1><form method='post'><input name='pma_username'><input type='password' name='pma_password'></form></body></html>"
    resp = web.Response(text=html, content_type="text/html")
    await _log_request(
        req,
        status=200,
        body=body,
        attack_type=str(atk),
        is_scanner=scanner,
        scanner_tool=scanner_tool,
        aggressive=aggressive,
    )
    return _attach_headers(resp)


async def handle_config_php(req: web.Request) -> web.Response:
    ip, _ = _peer(req)
    _, aggressive = _rate_state(ip)
    headers = extract_headers(req.headers)
    scanner, scanner_tool = classify_scanner(headers)
    body = await _read_body(req)
    text = "<?php define('DB_USER','dba'); define('DB_PASS','Sup3rWeak!'); define('DB_HOST','127.0.0.1'); ?>"
    resp = web.Response(text=text, content_type="application/octet-stream")
    await _log_request(
        req,
        status=200,
        body=body,
        attack_type="info_disclosure",
        is_scanner=scanner,
        scanner_tool=scanner_tool,
        aggressive=aggressive,
    )
    return _attach_headers(resp)


async def handle_env(req: web.Request) -> web.Response:
    ip, _ = _peer(req)
    _, aggressive = _rate_state(ip)
    headers = extract_headers(req.headers)
    scanner, scanner_tool = classify_scanner(headers)
    body = await _read_body(req)
    text = "DATABASE_URL=mysql://dba:changeme@db.internal/honeypot\nAPI_SECRET=TotallyFakeKey\nJWT_SECRET=insecurejwt\n"
    resp = web.Response(text=text, content_type="text/plain")
    await _log_request(
        req,
        status=200,
        body=body,
        attack_type="info_disclosure",
        is_scanner=scanner,
        scanner_tool=scanner_tool,
        aggressive=aggressive,
    )
    return _attach_headers(resp)


async def handle_etc_passwd(req: web.Request) -> web.Response:
    ip, _ = _peer(req)
    _, aggressive = _rate_state(ip)
    headers = extract_headers(req.headers)
    scanner, scanner_tool = classify_scanner(headers)
    body = await _read_body(req)
    text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nhoneypot:x:1001:1001::/home/honeypot:/bin/bash\n"
    resp = web.Response(text=text, content_type="text/plain")
    await _log_request(
        req,
        status=200,
        body=body,
        attack_type="lfi",
        is_scanner=scanner,
        scanner_tool=scanner_tool,
        aggressive=aggressive,
    )
    return _attach_headers(resp)


async def handle_git_config(req: web.Request) -> web.Response:
    ip, _ = _peer(req)
    _, aggressive = _rate_state(ip)
    headers = extract_headers(req.headers)
    scanner, scanner_tool = classify_scanner(headers)
    body = await _read_body(req)
    text = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@gitlab.internal:infra/secrets.git\n"
    resp = web.Response(text=text, content_type="text/plain")
    await _log_request(
        req,
        status=200,
        body=body,
        attack_type="info_disclosure",
        is_scanner=scanner,
        scanner_tool=scanner_tool,
        aggressive=aggressive,
    )
    return _attach_headers(resp)


async def handle_api_users(req: web.Request) -> web.Response:
    ip, _ = _peer(req)
    _, aggressive = _rate_state(ip)
    headers = extract_headers(req.headers)
    scanner, scanner_tool = classify_scanner(headers)
    body = await _read_body(req)
    payload = {
        "data": [{"id": 1, "username": "admin", "roles": ["admin"]}],
    }
    resp = web.Response(text=json.dumps(payload), content_type="application/json")
    await _log_request(
        req,
        status=200,
        body=body,
        attack_type="scanner_probe",
        is_scanner=scanner,
        scanner_tool=scanner_tool,
        aggressive=aggressive,
    )
    return _attach_headers(resp)


async def fallback(req: web.Request) -> web.Response:
    ip, _ = _peer(req)
    _, aggressive = _rate_state(ip)
    headers = extract_headers(req.headers)
    scanner, scanner_tool = classify_scanner(headers)
    body = await _read_body(req)
    attack = classify_attack(req.path_qs + body, body)
    atk = refine_attack_type(attack, req.path_qs + body, body)
    resp = await _render(req, "404.html", {"PATH": req.path})
    resp.set_status(404)
    await _log_request(
        req,
        status=404,
        body=body,
        attack_type=str(atk),
        is_scanner=scanner,
        scanner_tool=scanner_tool,
        aggressive=aggressive,
    )
    return _attach_headers(resp)
