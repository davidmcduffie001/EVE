"""Request-level tests for administrative user and role management."""

from uuid import uuid4

import anyio
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.database import create_sessionmaker
from app.main import create_app
from app.models.base import AuditLog, Base, Role, User
from app.services.auth.security import PasswordHasher


def _csrf_headers(client: TestClient) -> dict[str, str]:
    return {"x-csrf-token": client.cookies["eve_csrf_token"]}


@pytest.fixture
def admin_client() -> tuple[TestClient, async_sessionmaker[AsyncSession]]:
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
                permissions=["users:manage", "roles:manage", "audit:read"],
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


def _login(client: TestClient, email: str = "admin@example.test") -> None:
    response = client.post(
        "/auth/login",
        json={"email": email, "password": "correct-password"},
    )
    assert response.status_code == 200


def test_admin_can_list_users_and_roles(
    admin_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """Administrative users can list local users and roles."""
    client, _sessionmaker = admin_client
    _login(client)

    users_response = client.get("/admin/users")
    roles_response = client.get("/admin/roles")

    assert users_response.status_code == 200
    assert users_response.json()["total"] == 2
    assert users_response.json()["items"][0]["email"] == "admin@example.test"
    assert roles_response.status_code == 200
    assert [role["name"] for role in roles_response.json()["items"]] == ["Admin", "Analyst"]


def test_admin_can_read_and_update_sso_settings_stub(
    admin_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """Admins can configure the stubbed SSO settings surface."""
    client, _sessionmaker = admin_client
    _login(client)

    current = client.get("/admin/sso")
    updated = client.put(
        "/admin/sso",
        json={
            "enabled": True,
            "provider": "oidc",
            "display_name": "Corporate IdP",
            "issuer_url": "https://idp.example.test",
            "client_id": "eve-client",
            "metadata_url": "https://idp.example.test/.well-known/openid-configuration",
            "auto_provision": True,
            "default_role": "Analyst",
        },
        headers=_csrf_headers(client),
    )

    assert current.status_code == 200
    assert current.json()["enabled"] is False
    assert updated.status_code == 200
    assert updated.json()["enabled"] is True
    assert updated.json()["provider"] == "oidc"
    assert updated.json()["client_secret_configured"] is False


def test_non_admin_user_management_denial_is_audited(
    admin_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """Users without management permissions receive a denial that is audit-logged."""
    client, sessionmaker = admin_client
    _login(client, "analyst@example.test")

    response = client.get("/admin/users")

    async def fetch_denials() -> list[AuditLog]:
        async with sessionmaker() as session:
            return (
                await session.scalars(
                    select(AuditLog).where(AuditLog.action == "auth.permission_denied")
                )
            ).all()

    denials = anyio.run(fetch_denials)
    assert response.status_code == 403
    assert denials
    assert denials[-1].resource_id == "users:manage"


def test_admin_can_create_custom_role_and_user(
    admin_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """Admins can create a custom role and then create a user assigned to it."""
    client, _sessionmaker = admin_client
    _login(client)

    role_response = client.post(
        "/admin/roles",
        json={"name": "Triage", "permissions": ["findings:read", "reports:export"]},
        headers=_csrf_headers(client),
    )
    role_id = role_response.json()["id"]
    user_response = client.post(
        "/admin/users",
        json={
            "email": "triage@example.test",
            "display_name": "Triage User",
            "role_id": role_id,
            "password": "temporary-password",
        },
        headers=_csrf_headers(client),
    )

    assert role_response.status_code == 201
    assert role_response.json()["is_system_role"] is False
    assert user_response.status_code == 201
    assert user_response.json()["email"] == "triage@example.test"
    assert user_response.json()["role"]["name"] == "Triage"


def test_system_roles_cannot_be_deleted(
    admin_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """Built-in system roles are protected from deletion."""
    client, _sessionmaker = admin_client
    _login(client)
    roles_response = client.get("/admin/roles")
    admin_role = next(role for role in roles_response.json()["items"] if role["name"] == "Admin")

    response = client.delete(f"/admin/roles/{admin_role['id']}", headers=_csrf_headers(client))

    assert response.status_code == 400
    assert response.json() == {"detail": "System roles cannot be deleted"}


def test_admin_can_disable_user_and_disabled_user_cannot_login(
    admin_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """Admins can disable a local user account."""
    client, _sessionmaker = admin_client
    _login(client)
    users_response = client.get("/admin/users")
    analyst = next(
        user for user in users_response.json()["items"] if user["email"] == "analyst@example.test"
    )

    disable_response = client.patch(
        f"/admin/users/{analyst['id']}",
        json={"disabled": True},
        headers=_csrf_headers(client),
    )
    login_response = client.post(
        "/auth/login",
        json={"email": "analyst@example.test", "password": "correct-password"},
    )

    assert disable_response.status_code == 200
    assert disable_response.json()["disabled"] is True
    assert login_response.status_code == 403
    assert login_response.json() == {"detail": "Account is disabled"}


def test_built_in_admin_user_cannot_be_disabled(
    admin_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """The built-in local Admin account must remain enabled."""
    client, _sessionmaker = admin_client
    _login(client)
    users_response = client.get("/admin/users")
    admin = next(
        user for user in users_response.json()["items"] if user["email"] == "admin@example.test"
    )

    response = client.patch(
        f"/admin/users/{admin['id']}",
        json={"disabled": True},
        headers=_csrf_headers(client),
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Built-in Admin user cannot be disabled"}


def test_built_in_admin_user_role_cannot_be_changed(
    admin_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """The built-in local Admin account must retain the Admin role."""
    client, _sessionmaker = admin_client
    _login(client)
    users_response = client.get("/admin/users")
    roles_response = client.get("/admin/roles")
    admin = next(
        user for user in users_response.json()["items"] if user["email"] == "admin@example.test"
    )
    analyst_role = next(
        role for role in roles_response.json()["items"] if role["name"] == "Analyst"
    )

    response = client.patch(
        f"/admin/users/{admin['id']}",
        json={"role_id": analyst_role["id"]},
        headers=_csrf_headers(client),
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Built-in Admin user role cannot be changed"}


def test_admin_can_delete_user_account(
    admin_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """Admins can delete local user accounts that are not the built-in Admin."""
    client, _sessionmaker = admin_client
    _login(client)
    users_response = client.get("/admin/users")
    analyst = next(
        user for user in users_response.json()["items"] if user["email"] == "analyst@example.test"
    )

    response = client.delete(f"/admin/users/{analyst['id']}", headers=_csrf_headers(client))
    users_after_delete = client.get("/admin/users")
    login_response = client.post(
        "/auth/login",
        json={"email": "analyst@example.test", "password": "correct-password"},
    )

    assert response.status_code == 204
    assert "analyst@example.test" not in [
        user["email"] for user in users_after_delete.json()["items"]
    ]
    assert login_response.status_code == 401


def test_built_in_admin_user_cannot_be_deleted(
    admin_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """The built-in local Admin account must not be deletable."""
    client, _sessionmaker = admin_client
    _login(client)
    users_response = client.get("/admin/users")
    admin = next(
        user for user in users_response.json()["items"] if user["email"] == "admin@example.test"
    )

    response = client.delete(f"/admin/users/{admin['id']}", headers=_csrf_headers(client))

    assert response.status_code == 400
    assert response.json() == {"detail": "Built-in Admin user cannot be deleted"}


def test_admin_can_clear_user_mfa_configuration(
    admin_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """Admins can reset another user's MFA enrollment."""
    client, sessionmaker = admin_client
    _login(client)

    async def enroll_analyst_mfa() -> None:
        async with sessionmaker() as session:
            analyst = await session.scalar(
                select(User).where(User.email == "analyst@example.test")
            )
            assert analyst is not None
            analyst.mfa_enrolled = True
            analyst.mfa_secret = "JBSWY3DPEHPK3PXP"  # noqa: S105
            await session.commit()

    anyio.run(enroll_analyst_mfa)
    users_response = client.get("/admin/users")
    analyst = next(
        user for user in users_response.json()["items"] if user["email"] == "analyst@example.test"
    )

    response = client.delete(
        f"/admin/users/{analyst['id']}/mfa",
        headers=_csrf_headers(client),
    )

    async def fetch_analyst() -> User | None:
        async with sessionmaker() as session:
            return await session.scalar(select(User).where(User.email == "analyst@example.test"))

    stored_analyst = anyio.run(fetch_analyst)
    assert response.status_code == 200
    assert response.json()["mfa_enrolled"] is False
    assert stored_analyst is not None
    assert stored_analyst.mfa_enrolled is False
    assert stored_analyst.mfa_secret is None
