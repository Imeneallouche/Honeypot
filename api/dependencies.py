"""FastAPI dependency providers (database session + JWT user)."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from pipeline.database import get_session_factory


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    API_SECRET_KEY: str = Field(..., min_length=16)
    API_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "changeme"
    CORS_ORIGINS: str = "http://localhost:3000"


def get_settings() -> Settings:
    return Settings()


http_bearer = HTTPBearer(auto_error=False)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    factory = get_session_factory()
    async with factory() as session:
        yield session


get_db = get_db_session


class TokenClaims(BaseModel):
    sub: str
    token_type: str


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(http_bearer)],
    settings_dep: Annotated[Settings, Depends(get_settings)],
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    token = credentials.credentials
    try:
        payload_dict = jwt.decode(
            token,
            settings_dep.API_SECRET_KEY,
            algorithms=[settings_dep.API_ALGORITHM],
            options={"require_exp": True},
        )
        if payload_dict.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token scope")
        claims = TokenClaims.model_validate(
            {"sub": str(payload_dict.get("sub")), "token_type": str(payload_dict.get("type"))}
        )
        if not claims.sub:
            raise HTTPException(status_code=401, detail="Invalid subject")
        return claims.sub
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Could not validate token") from exc
