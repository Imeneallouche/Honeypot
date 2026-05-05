"""FastAPI composition root."""

from __future__ import annotations

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.auth import router as auth_router
from api.dependencies import get_settings
from api.routers import alerts, attackers, dashboard, honeypots, payloads, reports, sessions
from api.websocket import router as websocket_router
from pipeline.database import dispose_engine, init_models

API_VERSION = "1.0.0"


def _cors_origins(raw: str) -> list[str]:
    return [o.strip() for o in raw.split(",") if o.strip()]


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await init_models()
    yield
    await dispose_engine()


app = FastAPI(title="Honeypot Command Center", version=API_VERSION, lifespan=lifespan)
_settings = get_settings()

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(_settings.CORS_ORIGINS),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api")

for _router in (
    dashboard.router,
    sessions.router,
    attackers.router,
    payloads.router,
    alerts.router,
    reports.router,
    honeypots.router,
):
    app.include_router(_router, prefix="/api")

app.include_router(websocket_router, prefix="/ws")


@app.get("/api/health")
async def api_health() -> dict[str, str]:
    return {"status": "ok", "version": API_VERSION}
