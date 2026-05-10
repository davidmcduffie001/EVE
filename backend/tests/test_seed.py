"""Tests for idempotent baseline database seeding."""

import pytest
from sqlalchemy import select

from app.core.database import create_sessionmaker
from app.models.base import Base, ExploitIntelSource, Role, User
from app.services.auth.security import PasswordHasher
from app.services.bootstrap import (
    create_or_update_local_admin,
    seed_builtin_intel_sources,
    seed_builtin_roles,
)


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


@pytest.mark.asyncio
async def test_create_or_update_local_admin_creates_admin_user() -> None:
    """Local admin bootstrap creates an Admin user with a hashed password."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with sessionmaker() as session:
        documented_value = "correct-password"
        user = await create_or_update_local_admin(
            session,
            email="ADMIN@example.test",
            display_name="Admin User",
            **{"password": documented_value},
        )
        await session.commit()

    async with sessionmaker() as session:
        role = await session.scalar(select(Role).where(Role.name == "Admin"))
        stored_user = await session.scalar(select(User).where(User.email == "admin@example.test"))

    assert role is not None
    assert stored_user is not None
    assert user.email == "admin@example.test"
    assert stored_user.role_id == role.id
    assert stored_user.password_hash != documented_value
    assert PasswordHasher().verify_password(documented_value, stored_user.password_hash)


@pytest.mark.asyncio
async def test_create_or_update_local_admin_is_idempotent() -> None:
    """Re-running bootstrap updates the same local admin instead of duplicating it."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with sessionmaker() as session:
        first_value = "first-password"
        first_user = await create_or_update_local_admin(
            session,
            email="admin@example.test",
            display_name="Admin User",
            **{"password": first_value},
        )
        await session.commit()

    async with sessionmaker() as session:
        second_value = "second-password"
        second_user = await create_or_update_local_admin(
            session,
            email="admin@example.test",
            display_name="Updated Admin",
            **{"password": second_value},
        )
        await session.commit()

    async with sessionmaker() as session:
        users = (await session.scalars(select(User))).all()

    assert second_user.id == first_user.id
    assert len(users) == 1
    assert users[0].display_name == "Updated Admin"
    assert PasswordHasher().verify_password(second_value, users[0].password_hash)
