"""Request-level tests for scanner integration settings."""

from uuid import uuid4

import anyio
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.database import create_sessionmaker
from app.main import create_app
from app.models.base import AuditLog, Base, Role, ScannerIntegration, User
from app.services.auth.security import PasswordHasher


def _csrf_headers(client: TestClient) -> dict[str, str]:
    return {"x-csrf-token": client.cookies["eve_csrf_token"]}


@pytest.fixture
def scanner_client() -> tuple[TestClient, async_sessionmaker[AsyncSession]]:
    """Create a test app with scanner administrator and analyst users."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")

    async def seed() -> None:
        async with sessionmaker.kw["bind"].begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        async with sessionmaker() as session:
            scanner_role = Role(
                id=uuid4(),
                name="Scanner Admin",
                is_system_role=False,
                permissions=["scanners:manage"],
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
                    email="scanner-admin@example.test",
                    display_name="Scanner Admin",
                    role_id=scanner_role.id,
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
            session.add_all([scanner_role, analyst_role, *users])
            await session.commit()

    anyio.run(seed)
    settings = Settings(auth_secret_key="test-signing-key", cookie_secure=False)  # noqa: S106
    with TestClient(create_app(settings=settings, sessionmaker=sessionmaker)) as client:
        yield client, sessionmaker

    anyio.run(sessionmaker.kw["bind"].dispose)


def _login(client: TestClient, email: str = "scanner-admin@example.test") -> None:
    response = client.post(
        "/auth/login",
        json={"email": email, "password": "correct-password"},
    )
    assert response.status_code == 200


def test_scanner_manager_can_create_and_list_nessus_integration(
    scanner_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """Scanner administrators can create and list Nessus integrations without secret leakage."""
    client, sessionmaker = scanner_client
    _login(client)

    response = client.post(
        "/settings/scanners",
        json={
            "name": "Production Nessus",
            "scanner_type": "nessus",
            "base_url": "https://nessus.example.test:8834",
            "access_key": "nessus-access-key",
            "secret_key": "nessus-secret-key",
            "enabled": True,
        },
        headers=_csrf_headers(client),
    )
    list_response = client.get("/settings/scanners")

    async def fetch_integration() -> ScannerIntegration | None:
        async with sessionmaker() as session:
            return await session.scalar(select(ScannerIntegration))

    stored = anyio.run(fetch_integration)

    assert response.status_code == 201
    assert response.json()["name"] == "Production Nessus"
    assert response.json()["scanner_type"] == "nessus"
    assert response.json()["last_sync_status"] == "never_run"
    assert "nessus-secret-key" not in response.text
    assert list_response.status_code == 200
    assert list_response.json()["total"] == 1
    assert list_response.json()["items"][0]["name"] == "Production Nessus"
    assert stored is not None
    assert stored.encrypted_credentials_ref.startswith("v1:")
    assert "nessus-access-key" not in stored.encrypted_credentials_ref
    assert "nessus-secret-key" not in stored.encrypted_credentials_ref


def test_scanner_manager_can_update_and_delete_integration(
    scanner_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """Scanner administrators can maintain integration metadata and remove integrations."""
    client, _sessionmaker = scanner_client
    _login(client)
    created = client.post(
        "/settings/scanners",
        json={
            "name": "Nessus",
            "scanner_type": "nessus",
            "base_url": "https://nessus.example.test:8834",
            "access_key": "access-key",
            "secret_key": "secret-key",
            "enabled": True,
        },
        headers=_csrf_headers(client),
    )
    integration_id = created.json()["id"]

    updated = client.patch(
        f"/settings/scanners/{integration_id}",
        json={"name": "Nessus Disabled", "enabled": False},
        headers=_csrf_headers(client),
    )
    deleted = client.delete(
        f"/settings/scanners/{integration_id}",
        headers=_csrf_headers(client),
    )
    list_response = client.get("/settings/scanners")

    assert created.status_code == 201
    assert updated.status_code == 200
    assert updated.json()["name"] == "Nessus Disabled"
    assert updated.json()["enabled"] is False
    assert deleted.status_code == 204
    assert list_response.json()["total"] == 0


def test_scanner_management_requires_permission_and_csrf(
    scanner_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """Scanner routes require scanners:manage and CSRF protection for writes."""
    client, _sessionmaker = scanner_client
    _login(client, "analyst@example.test")

    denied_list = client.get("/settings/scanners")
    denied_create = client.post(
        "/settings/scanners",
        json={
            "name": "Nessus",
            "scanner_type": "nessus",
            "base_url": "https://nessus.example.test:8834",
            "access_key": "access-key",
            "secret_key": "secret-key",
            "enabled": True,
        },
        headers=_csrf_headers(client),
    )
    _login(client)
    missing_csrf = client.post(
        "/settings/scanners",
        json={
            "name": "Nessus",
            "scanner_type": "nessus",
            "base_url": "https://nessus.example.test:8834",
            "access_key": "access-key",
            "secret_key": "secret-key",
            "enabled": True,
        },
    )

    assert denied_list.status_code == 403
    assert denied_create.status_code == 403
    assert missing_csrf.status_code == 403


def test_scanner_create_audit_log_omits_credentials(
    scanner_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """Scanner credential values are never written into audit metadata."""
    client, sessionmaker = scanner_client
    _login(client)

    response = client.post(
        "/settings/scanners",
        json={
            "name": "Production Nessus",
            "scanner_type": "nessus",
            "base_url": "https://nessus.example.test:8834",
            "access_key": "nessus-access-key",
            "secret_key": "nessus-secret-key",
            "enabled": True,
        },
        headers=_csrf_headers(client),
    )

    async def fetch_audit_event() -> AuditLog | None:
        async with sessionmaker() as session:
            return await session.scalar(
                select(AuditLog).where(AuditLog.action == "settings.scanner_create")
            )

    event = anyio.run(fetch_audit_event)

    assert response.status_code == 201
    assert event is not None
    assert event.metadata_json["scanner_type"] == "nessus"
    assert "nessus-access-key" not in str(event.metadata_json)
    assert "nessus-secret-key" not in str(event.metadata_json)
