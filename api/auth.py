"""Authentication utilities and routes (JWT access + refresh)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt

from api.dependencies import Settings, get_settings
from api.schemas import RefreshRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["auth"])


def _exp_ts(delta: timedelta) -> int:
    return int((datetime.now(timezone.utc) + delta).timestamp())


def create_access_token(subject: str, settings: Settings) -> str:
    expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": subject,
        "type": "access",
        "exp": _exp_ts(expires),
        "iat": int(datetime.now(timezone.utc).timestamp()),
    }
    return jwt.encode(payload, settings.API_SECRET_KEY, algorithm=settings.API_ALGORITHM)


def create_refresh_token(subject: str, settings: Settings) -> str:
    expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": subject,
        "type": "refresh",
        "exp": _exp_ts(expires),
        "iat": int(datetime.now(timezone.utc).timestamp()),
    }
    return jwt.encode(payload, settings.API_SECRET_KEY, algorithm=settings.API_ALGORITHM)


def authenticate_operator(username: str, password: str, settings: Settings) -> None:
    if username != settings.ADMIN_USERNAME:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect credentials")
    if password != settings.ADMIN_PASSWORD:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect credentials")


@router.post("/login", response_model=TokenResponse)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenResponse:
    authenticate_operator(form_data.username, form_data.password, settings)
    subject = settings.ADMIN_USERNAME
    return TokenResponse(
        access_token=create_access_token(subject, settings),
        refresh_token=create_refresh_token(subject, settings),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_tokens(
    body: RefreshRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenResponse:
    try:
        payload = jwt.decode(
            body.refresh_token,
            settings.API_SECRET_KEY,
            algorithms=[settings.API_ALGORITHM],
            options={"require_exp": True},
        )
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from exc

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token scope")

    subject = str(payload.get("sub") or "")
    if not subject:
        raise HTTPException(status_code=401, detail="Invalid refresh subject")

    return TokenResponse(
        access_token=create_access_token(subject, settings),
        refresh_token=create_refresh_token(subject, settings),
    )
