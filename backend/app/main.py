"""FastAPI application entrypoint for EVE."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.core.database import create_sessionmaker
from app.core.logging import configure_logging
from app.routers.auth import create_auth_router


def create_app(
    settings: Settings | None = None,
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application."""
    active_settings = settings or get_settings()
    active_sessionmaker = sessionmaker or create_sessionmaker(active_settings.database_url)
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

    app.include_router(create_auth_router(active_settings, active_sessionmaker))

    return app


app = create_app()
