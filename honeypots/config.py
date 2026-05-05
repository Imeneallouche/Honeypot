"""Shared configuration for honeypots (Pydantic Settings)."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class HoneypotSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    SSH_HONEYPOT_PORT: int = 2222
    HTTP_HONEYPOT_PORT: int = 8080
    SSH_HOST_KEY_PATH: str = "./data/ssh_host_key"
    SSH_FAKE_HOSTNAME: str = "web-prod-ubuntu"
    LOG_DIR: str = "./logs"
    TARPIT_THRESHOLD: int = 10
    TARPIT_DELAY_MS: int = 750


def settings() -> HoneypotSettings:
    return HoneypotSettings()


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]
