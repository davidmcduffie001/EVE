"""Application configuration loaded from environment variables."""

from functools import lru_cache

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for the EVE backend."""

    model_config = SettingsConfigDict(env_prefix="EVE_", env_file=".env", extra="ignore")

    env: str = "development"
    log_level: str = "INFO"
    public_base_url: AnyHttpUrl = "http://localhost:5173"
    api_base_url: AnyHttpUrl = "http://localhost:8000"
    database_url: str = "postgresql+asyncpg://eve:eve_dev_password@127.0.0.1:5432/eve_dev"
    redis_url: str = "redis://127.0.0.1:6379/0"
    celery_broker_url: str = "redis://127.0.0.1:6379/1"
    celery_result_backend: str = "redis://127.0.0.1:6379/2"
    cookie_secure: bool = False
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    auth_secret_key: str = Field(
        default_factory=lambda: "eve-development-auth-signing-key-change-before-production"
    )
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 60 * 60 * 24 * 30
    access_cookie_name: str = "eve_access_token"
    refresh_cookie_name: str = "eve_refresh_token"
    csrf_cookie_name: str = "eve_csrf_token"
    csrf_header_name: str = "x-csrf-token"
    cookie_samesite: str = "strict"


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()
