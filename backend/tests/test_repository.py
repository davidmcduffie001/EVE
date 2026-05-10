"""Tests for simple repository primitives."""

import pytest

from app.core.database import create_sessionmaker
from app.models.base import Base, Target
from app.repositories.base import SqlAlchemyRepository


@pytest.mark.asyncio
async def test_repository_adds_and_fetches_model_by_id() -> None:
    """The base repository persists and fetches ORM models by primary key."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with sessionmaker() as session:
        repository = SqlAlchemyRepository[Target](session, Target)
        target = await repository.add(
            Target(locator="10.0.0.1", locator_type="ip", in_authorized_scope=True)
        )
        fetched = await repository.get(target.id)

    assert fetched is target
    assert fetched.locator == "10.0.0.1"

