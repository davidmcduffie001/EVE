"""Request-level tests for administrative user and role management."""

from uuid import uuid4

import anyio
import pytest
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.database import create_sessionmaker
from app.main import create_app
from app.models.base import AuditLog, Base, Role, SsoConfiguration, User
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


def test_admin_can_read_and_update_persisted_sso_settings(
    admin_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """Admins can configure persisted SAML or OIDC SSO settings."""
    client, sessionmaker = admin_client
    _login(client)

    current = client.get("/admin/sso")
    updated = client.put(
        "/admin/sso",
        json={
            "enabled": True,
            "provider": "saml",
            "display_name": "Corporate SAML",
            "issuer_url": "https://idp.example.test/saml",
            "client_id": "eve-saml-sp",
            "metadata_url": "https://idp.example.test/metadata.xml",
            "client_secret": "super-sensitive-secret",
            "auto_provision": True,
            "default_role": "Analyst",
        },
        headers=_csrf_headers(client),
    )
    fresh_app = create_app(
        settings=Settings(auth_secret_key="test-signing-key", cookie_secure=False),  # noqa: S106
        sessionmaker=sessionmaker,
    )
    with TestClient(fresh_app) as fresh_client:
        _login(fresh_client)
        persisted = fresh_client.get("/admin/sso")

    async def fetch_sso_configuration() -> SsoConfiguration | None:
        async with sessionmaker() as session:
            return await session.get(SsoConfiguration, "default")

    stored = anyio.run(fetch_sso_configuration)

    assert current.status_code == 200
    assert current.json()["enabled"] is False
    assert updated.status_code == 200
    assert updated.json()["enabled"] is True
    assert updated.json()["provider"] == "saml"
    assert updated.json()["client_secret_configured"] is True
    assert "super-sensitive-secret" not in updated.text
    assert persisted.status_code == 200
    assert persisted.json()["display_name"] == "Corporate SAML"
    assert persisted.json()["client_secret_configured"] is True
    assert stored is not None
    assert stored.provider == "saml"
    assert stored.encrypted_client_secret is not None
    assert "super-sensitive-secret" not in stored.encrypted_client_secret


def test_admin_can_validate_oidc_sso_configuration(
    admin_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Admins can validate persisted OIDC discovery and JWKS settings before enabling SSO."""
    client, sessionmaker = admin_client
    _login(client)

    class FakeAsyncClient:
        def __init__(self, *, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self) -> FakeAsyncClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def get(self, url: str) -> HttpxResponse:
            if url == "https://idp.example.test/.well-known/openid-configuration":
                return HttpxResponse(
                    200,
                    json={
                        "issuer": "https://idp.example.test",
                        "token_endpoint": "https://idp.example.test/token",
                        "userinfo_endpoint": "https://idp.example.test/userinfo",
                        "jwks_uri": "https://idp.example.test/jwks",
                    },
                )
            assert url == "https://idp.example.test/jwks"
            return HttpxResponse(200, json={"keys": [{"kid": "one"}]})

    monkeypatch.setattr("app.routers.admin.httpx.AsyncClient", FakeAsyncClient)

    update_response = client.put(
        "/admin/sso",
        json={
            "enabled": False,
            "provider": "oidc",
            "display_name": "Corporate IdP",
            "issuer_url": "https://idp.example.test",
            "client_id": "eve-client",
            "metadata_url": "",
            "auto_provision": False,
            "default_role": "Analyst",
        },
        headers=_csrf_headers(client),
    )
    response = client.post("/admin/sso/validate", headers=_csrf_headers(client))

    async def fetch_validation_events() -> list[AuditLog]:
        async with sessionmaker() as session:
            return (
                await session.scalars(
                    select(AuditLog).where(AuditLog.action == "admin.sso_validate")
                )
            ).all()

    validation_events = anyio.run(fetch_validation_events)
    payload = response.json()

    assert update_response.status_code == 200
    assert response.status_code == 200
    assert payload["valid"] is True
    assert payload["provider"] == "oidc"
    assert payload["redirect_uri"] == "http://localhost:8001/auth/sso/oidc/callback"
    assert {check["name"]: check["passed"] for check in payload["checks"]}["JWKS keys"] is True
    assert validation_events
    assert validation_events[-1].metadata_json["valid"] is True


def test_admin_can_validate_saml_sso_configuration(
    admin_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Admins can validate persisted SAML IdP metadata before enabling SSO."""
    client, _sessionmaker = admin_client
    _login(client)

    class FakeAsyncClient:
        def __init__(self, *, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self) -> FakeAsyncClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def get(self, url: str) -> HttpxResponse:
            assert url == "https://idp.example.test/metadata.xml"
            return HttpxResponse(
                200,
                text=(
                    '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
                    'entityID="https://idp.example.test/saml">'
                    '<IDPSSODescriptor protocolSupportEnumeration='
                    '"urn:oasis:names:tc:SAML:2.0:protocol">'
                    '<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
                    "<X509Data><X509Certificate>MIIDfake</X509Certificate></X509Data>"
                    "</KeyInfo></KeyDescriptor>"
                    '<SingleSignOnService Binding='
                    '"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
                    'Location="https://idp.example.test/sso" />'
                    "</IDPSSODescriptor>"
                    "</EntityDescriptor>"
                ),
            )

    monkeypatch.setattr("app.routers.admin.httpx.AsyncClient", FakeAsyncClient)

    update_response = client.put(
        "/admin/sso",
        json={
            "enabled": False,
            "provider": "saml",
            "display_name": "Corporate SAML",
            "issuer_url": "https://idp.example.test/saml",
            "client_id": "eve-saml-sp",
            "metadata_url": "https://idp.example.test/metadata.xml",
            "auto_provision": False,
            "default_role": "Analyst",
        },
        headers=_csrf_headers(client),
    )
    response = client.post("/admin/sso/validate", headers=_csrf_headers(client))
    payload = response.json()

    assert update_response.status_code == 200
    assert response.status_code == 200
    assert payload["valid"] is True
    assert payload["provider"] == "saml"
    assert payload["redirect_uri"] == "http://localhost:8001/auth/sso/saml/acs"
    checks = {check["name"]: check["passed"] for check in payload["checks"]}
    assert checks["SAML metadata"] is True
    assert checks["IdP SSO service"] is True
    assert checks["Signing certificate"] is True


def test_admin_saml_validation_reports_missing_metadata_url(
    admin_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """SAML validation reports missing metadata separately from OIDC requirements."""
    client, _sessionmaker = admin_client
    _login(client)

    update_response = client.put(
        "/admin/sso",
        json={
            "enabled": False,
            "provider": "saml",
            "display_name": "Corporate SAML",
            "issuer_url": "https://idp.example.test/saml",
            "client_id": "eve-saml-sp",
            "metadata_url": "",
            "auto_provision": False,
            "default_role": "Analyst",
        },
        headers=_csrf_headers(client),
    )
    response = client.post("/admin/sso/validate", headers=_csrf_headers(client))
    payload = response.json()

    assert update_response.status_code == 200
    assert response.status_code == 200
    assert payload["valid"] is False
    assert {check["name"]: check["passed"] for check in payload["checks"]}["Metadata URL"] is False


def test_admin_sso_validation_reports_missing_oidc_configuration(
    admin_client: tuple[TestClient, async_sessionmaker[AsyncSession]],
) -> None:
    """SSO validation returns structured failed checks instead of a generic server error."""
    client, _sessionmaker = admin_client
    _login(client)

    response = client.post("/admin/sso/validate", headers=_csrf_headers(client))
    payload = response.json()

    assert response.status_code == 200
    assert payload["valid"] is False
    assert {check["name"]: check["passed"] for check in payload["checks"]}["Issuer URL"] is False
    assert {check["name"]: check["passed"] for check in payload["checks"]}["Client ID"] is False


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
