"""WebSocket helpers for `/ws/live-feed` with broadcasts and JWT auth."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import Settings, get_settings
from pipeline.database import get_session_factory
from pipeline.models import FeedEvent

router = APIRouter(tags=["websocket"])


class ConnectionManager:
    def __init__(self) -> None:
        self._active: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._active.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        try:
            self._active.remove(ws)
        except ValueError:
            pass

    async def broadcast(self, data: dict[str, Any]) -> None:
        body = json.dumps(data, default=str)
        async with self._lock:
            targets = list(self._active)
        dead: list[WebSocket] = []
        for c in targets:
            try:
                await c.send_text(body)
            except Exception:
                dead.append(c)
        for c in dead:
            self.disconnect(c)


manager = ConnectionManager()


async def broadcast_feed_event(message: dict[str, Any]) -> None:
    """Multi-process setups still rely on polling; callers in the API reuse this hub."""
    await manager.broadcast(message)


def _flag_from_country(label: str | None) -> str:
    if not label or len(label) < 2:
        return ""
    core = "".join(ch for ch in label[:6] if ch.isalpha())[:2]
    if len(core) != 2:
        return ""
    a, b = core.upper()
    if not ("A" <= a <= "Z" and "A" <= b <= "Z"):
        return ""
    return chr(ord(a) + 127397) + chr(ord(b) + 127397)


async def _verify_access_token(raw_token: str, settings: Settings) -> None:
    try:
        payload = jwt.decode(
            raw_token,
            settings.API_SECRET_KEY,
            algorithms=[settings.API_ALGORITHM],
            options={"require_exp": True},
        )
    except JWTError as exc:
        raise PermissionError("invalid jwt") from exc
    if payload.get("type") != "access" or not payload.get("sub"):
        raise PermissionError("jwt scope")


def _serialize_evt(evt: FeedEvent) -> dict[str, Any]:
    country_iso = evt.country if isinstance(evt.country, str) else None
    return {
        "event_type": evt.event_type,
        "detail": evt.detail,
        "src_ip": evt.src_ip,
        "honeypot_type": evt.honeypot_type,
        "timestamp": evt.timestamp.isoformat(),
        "country": country_iso,
        "flag": _flag_from_country(country_iso[:2]) if country_iso else "",
    }


async def _latest_feed_id(session: AsyncSession) -> int:
    res = await session.execute(select(FeedEvent.id).order_by(FeedEvent.id.desc()).limit(1))
    value = res.scalar_one_or_none()
    return int(value or 0)




@router.websocket("/live-feed")
async def live_feed_socket(websocket: WebSocket) -> None:
    settings = get_settings()
    bearer = websocket.query_params.get("token")
    try:
        if not bearer:
            raise PermissionError("missing token")
        await _verify_access_token(bearer, settings)
    except PermissionError:
        await websocket.close(code=4401)
        return

    await manager.connect(websocket)
    factory = get_session_factory()
    async with factory() as session:
        last_holder = {"id": await _latest_feed_id(session)}

    loop_time = asyncio.get_event_loop().time()
    ping_at = loop_time + 30.0

    try:
        while True:
            now = asyncio.get_event_loop().time()
            if now >= ping_at:
                await websocket.send_text(json.dumps({"type": "ping"}))
                ping_at = now + 30.0

            async with factory() as sess:
                rows = (
                    (
                        await sess.execute(
                            select(FeedEvent)
                            .where(FeedEvent.id > last_holder["id"])
                            .order_by(FeedEvent.id.asc())
                            .limit(25)
                        )
                    )
                    .scalars()
                    .all()
                )
                for evt in rows:
                    last_holder["id"] = evt.id
                    await websocket.send_text(json.dumps(_serialize_evt(evt)))

            try:
                await asyncio.wait_for(websocket.receive(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except WebSocketDisconnect:
                break
    finally:
        manager.disconnect(websocket)


__all__ = ["router", "manager", "broadcast_feed_event"]
