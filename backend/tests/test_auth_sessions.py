"""Tests for persistent refresh session handling."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.database import create_sessionmaker
from app.models.base import Base, RefreshSession, Role, User
from app.services.auth.sessions import RefreshSessionService


@pytest.mark.asyncio
async def test_refresh_session_service_creates_hashed_persistent_session() -> None:
    """Issued refresh tokens are returned once and stored only as hashes."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    user_id = uuid4()
    async with sessionmaker() as session:
        role = Role(id=uuid4(), name="admin", is_system_role=True, permissions=["*"])
        user = User(
            id=user_id,
            email="admin@example.test",
            display_name="Admin",
            role_id=role.id,
            password_hash="placeholder",  # noqa: S106
        )
        session.add_all([role, user])
        await session.flush()

        service = RefreshSessionService(session)
        issued = await service.issue_session(
            user_id=user_id,
            expires_at=datetime.now(UTC) + timedelta(days=30),
            user_agent="pytest",
            source_ip="127.0.0.1",
        )
        await session.commit()

    async with sessionmaker() as session:
        session_row = await session.scalar(select(RefreshSession))

    assert session_row is not None
    assert session_row.user_id == user_id
    assert session_row.refresh_token_hash != issued.refresh_token
    assert service.hash_refresh_token(issued.refresh_token) == session_row.refresh_token_hash
    assert session_row.user_agent == "pytest"
    assert session_row.source_ip == "127.0.0.1"
    assert session_row.revoked_at is None


@pytest.mark.asyncio
async def test_refresh_session_service_revokes_active_session() -> None:
    """A valid refresh token can be resolved, then revoked."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    user_id = uuid4()
    async with sessionmaker() as session:
        role = Role(id=uuid4(), name="admin", is_system_role=True, permissions=["*"])
        user = User(
            id=user_id,
            email="admin@example.test",
            display_name="Admin",
            role_id=role.id,
            password_hash="placeholder",  # noqa: S106
        )
        session.add_all([role, user])
        await session.flush()

        service = RefreshSessionService(session)
        issued = await service.issue_session(
            user_id=user_id,
            expires_at=datetime.now(UTC) + timedelta(days=30),
        )
        active_session = await service.get_active_session(issued.refresh_token)
        await service.revoke_session(issued.refresh_token)
        revoked_session = await service.get_active_session(issued.refresh_token)

    assert active_session is not None
    assert active_session.user_id == user_id
    assert revoked_session is None
