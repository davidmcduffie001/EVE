"""Tests for idempotent baseline database seeding."""

import pytest
from sqlalchemy import select

from app.core.database import create_sessionmaker
from app.models.base import Base, ExploitIntelSource, Role
from app.services.bootstrap import seed_builtin_intel_sources, seed_builtin_roles


@pytest.mark.asyncio
async def test_seed_builtin_roles_is_idempotent() -> None:
    """Built-in roles are inserted once and can be safely reseeded."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with sessionmaker() as session:
        await seed_builtin_roles(session)
        await seed_builtin_roles(session)
        rows = (await session.execute(select(Role).order_by(Role.name))).scalars().all()

    assert [row.name for row in rows] == ["Admin", "Analyst", "Read-Only"]
    assert all(row.is_system_role for row in rows)
    admin = next(row for row in rows if row.name == "Admin")
    assert "users:manage" in admin.permissions
    assert "scanners:manage" in admin.permissions


@pytest.mark.asyncio
async def test_seed_builtin_intel_sources_is_idempotent() -> None:
    """Built-in NVD and SearchSploit sources are inserted once and immutable."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with sessionmaker() as session:
        await seed_builtin_intel_sources(session)
        await seed_builtin_intel_sources(session)
        rows = (
            await session.execute(select(ExploitIntelSource).order_by(ExploitIntelSource.provider))
        ).scalars().all()

    assert [row.provider for row in rows] == ["nvd", "searchsploit"]
    assert all(row.built_in for row in rows)
    assert all(row.edition_required == "ce" for row in rows)
    assert rows[0].source_class == "vulnerability_enrichment"
    assert rows[1].source_class == "exploit_intelligence_metadata"

