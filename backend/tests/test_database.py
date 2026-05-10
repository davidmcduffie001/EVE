"""Tests for async database engine and session helpers."""

from collections.abc import AsyncIterator

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import create_sessionmaker, get_db_session
from app.models.base import Base


@pytest.mark.asyncio
async def test_create_sessionmaker_executes_queries() -> None:
    """The async sessionmaker creates working SQLAlchemy sessions."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")

    async with sessionmaker() as session:
        result = await session.execute(text("select 1"))

    assert result.scalar_one() == 1


@pytest.mark.asyncio
async def test_get_db_session_yields_and_closes_session() -> None:
    """The FastAPI dependency yields an AsyncSession and closes it afterward."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    dependency = get_db_session(sessionmaker)

    session_iterator: AsyncIterator[AsyncSession] = dependency()
    session = await anext(session_iterator)

    assert isinstance(session, AsyncSession)

    with pytest.raises(StopAsyncIteration):
        await anext(session_iterator)


@pytest.mark.asyncio
async def test_phase_1_metadata_can_create_all_tables() -> None:
    """The ORM metadata can create the full Phase 1 schema on an async engine."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")

    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        result = await connection.execute(
            text("select name from sqlite_master where type = 'table' order by name")
        )

    tables = {row[0] for row in result}
    assert "users" in tables
    assert "scanner_integrations" in tables
    assert "execution_jobs" not in tables

