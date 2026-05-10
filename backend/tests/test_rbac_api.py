"""Request-level tests for RBAC enforcement and audit-log access."""

from uuid import uuid4

import anyio
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import Settings
from app.core.database import create_sessionmaker
from app.main import create_app
from app.models.base import AuditLog, Base, Role, User
from app.services.auth.security import PasswordHasher


@pytest.fixture
def rbac_client() -> tuple[TestClient, object]:
    """Create a test app with admin and analyst users."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")

    async def seed() -> None:
        async with sessionmaker.kw["bind"].begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        async with sessionmaker() as session:
            admin_role = Role(
                id=uuid4(),
                name="Admin",
                is_system_role=True,
                permissions=["users:manage", "audit:read"],
            )
            analyst_role = Role(
                id=uuid4(),
                name="Analyst",
                is_system_role=True,
                permissions=["findings:read"],
            )
            users = [
                User(
                    id=uuid4(),
                    email="admin@example.test",
                    display_name="Admin User",
                    role_id=admin_role.id,
                    password_hash=PasswordHasher().hash_password("correct-password"),
                ),
                User(
                    id=uuid4(),
                    email="analyst@example.test",
                    display_name="Analyst User",
                    role_id=analyst_role.id,
                    password_hash=PasswordHasher().hash_password("correct-password"),
                ),
            ]
            session.add_all([admin_role, analyst_role, *users])
            await session.commit()

    anyio.run(seed)
    settings = Settings(auth_secret_key="test-signing-key", cookie_secure=False)  # noqa: S106
    with TestClient(create_app(settings=settings, sessionmaker=sessionmaker)) as client:
        yield client, sessionmaker

    anyio.run(sessionmaker.kw["bind"].dispose)


def test_audit_log_endpoint_requires_audit_read_permission(
    rbac_client: tuple[TestClient, object],
) -> None:
    """Authenticated users without audit permission cannot read audit events."""
    client, sessionmaker = rbac_client
    login = client.post(
        "/auth/login",
        json={"email": "analyst@example.test", "password": "correct-password"},
    )
    assert login.status_code == 200

    response = client.get("/admin/audit-log")

    assert response.status_code == 403
    assert response.json() == {"detail": "Permission denied"}

    async def fetch_denial_actions() -> list[str]:
        async with sessionmaker() as session:
            rows = (await session.scalars(select(AuditLog))).all()
            return [row.action for row in rows]

    assert "auth.permission_denied" in anyio.run(fetch_denial_actions)


def test_audit_log_endpoint_returns_paginated_entries_for_admin(
    rbac_client: tuple[TestClient, object],
) -> None:
    """Users with audit permission can read audit events through a paginated API."""
    client, _sessionmaker = rbac_client
    login = client.post(
        "/auth/login",
        json={"email": "admin@example.test", "password": "correct-password"},
    )
    assert login.status_code == 200

    response = client.get("/admin/audit-log")

    assert response.status_code == 200
    body = response.json()
    assert body["page"] == 1
    assert body["page_size"] == 50
    assert body["total"] >= 1
    assert body["items"][0]["action"] == "auth.login"
    assert body["items"][0]["outcome"] == "success"
