"""Async SQLAlchemy engine, session, and FastAPI dependency helpers."""

from collections.abc import AsyncIterator, Callable

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings


def create_engine(database_url: str, *, echo: bool = False) -> AsyncEngine:
    """Create an async SQLAlchemy engine for the configured database URL."""
    return create_async_engine(database_url, echo=echo, pool_pre_ping=True)


def create_sessionmaker(database_url: str) -> async_sessionmaker[AsyncSession]:
    """Create an async sessionmaker bound to a database engine."""
    engine = create_engine(database_url)
    return async_sessionmaker(engine, expire_on_commit=False)


SessionDependency = Callable[[], AsyncIterator[AsyncSession]]


def get_db_session(
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
) -> SessionDependency:
    """Create a FastAPI dependency that yields one async DB session per request."""
    active_sessionmaker = sessionmaker or create_sessionmaker(get_settings().database_url)

    async def dependency() -> AsyncIterator[AsyncSession]:
        async with active_sessionmaker() as session:
            yield session

    return dependency

