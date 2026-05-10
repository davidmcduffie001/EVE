"""Tests for backend runtime configuration defaults."""

from app.core.config import Settings


def test_development_ports_match_local_frontend_and_backend() -> None:
    """Defaults align with Vite on 8000 and the API on 8001."""
    settings = Settings()

    assert str(settings.public_base_url) == "http://localhost:8000/"
    assert str(settings.api_base_url) == "http://localhost:8001/"
    assert "http://localhost:8000" in settings.cors_origins
