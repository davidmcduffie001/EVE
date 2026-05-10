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


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()
