"""FastAPI application entrypoint for EVE."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import Settings, get_settings
from app.core.logging import configure_logging


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    active_settings = settings or get_settings()
    configure_logging(active_settings.log_level)

    app = FastAPI(
        title="EVE API",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=active_settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health", tags=["System"])
    async def health() -> dict[str, str]:
        """Return service health for unauthenticated liveness checks."""
        return {"status": "ok", "service": "eve-api"}

    return app


app = create_app()

