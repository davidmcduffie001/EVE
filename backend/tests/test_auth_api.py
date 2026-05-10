"""Request-level tests for authentication endpoints."""

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import anyio
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select

from app.core.config import Settings
from app.core.database import create_sessionmaker
from app.main import create_app
from app.models.base import Base, RefreshSession, Role, SsoConfiguration, User
from app.services.auth.mfa import generate_totp_code
from app.services.auth.security import PasswordHasher
from app.services.auth.sessions import RefreshSessionService


def _csrf_headers(client: TestClient) -> dict[str, str]:
    return {"x-csrf-token": client.cookies["eve_csrf_token"]}


def _signed_oidc_token(
    *,
    issuer: str = "https://idp.example.test",
    audience: str = "eve-client",
    nonce: str = "expected-nonce",
    key_id: str = "test-key",
) -> tuple[str, dict[str, object]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    public_jwk["kid"] = key_id
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "user-123",
            "iss": issuer,
            "aud": audience,
            "nonce": nonce,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": key_id},
    )
    return token, public_jwk


@pytest.fixture
def auth_client() -> TestClient:
    """Create a test app with one local admin user."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")

    async def seed() -> None:
        async with sessionmaker.kw["bind"].begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        async with sessionmaker() as session:
            role = Role(id=uuid4(), name="Admin", is_system_role=True, permissions=["*"])
            user = User(
                id=uuid4(),
                email="admin@example.test",
                display_name="Admin User",
                role_id=role.id,
                password_hash=PasswordHasher().hash_password("correct-password"),
            )
            session.add_all([role, user])
            await session.commit()

    import anyio

    anyio.run(seed)
    signing_key = "test-signing-key"
    settings = Settings(
        auth_secret_key=signing_key,
        cookie_secure=False,
        access_token_ttl_seconds=900,
        refresh_token_ttl_seconds=2_592_000,
    )
    with TestClient(create_app(settings=settings, sessionmaker=sessionmaker)) as client:
        yield client

    anyio.run(sessionmaker.kw["bind"].dispose)


def test_login_rejects_invalid_credentials_without_setting_cookies(
    auth_client: TestClient,
) -> None:
    """Invalid login attempts receive a generic auth failure."""
    response = auth_client.post(
        "/auth/login",
        json={"email": "admin@example.test", "password": "wrong-password"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password"}
    assert "eve_access_token" not in auth_client.cookies
    assert "eve_refresh_token" not in auth_client.cookies


def test_login_sets_http_only_session_cookies(auth_client: TestClient) -> None:
    """Valid credentials set access and refresh cookies."""
    response = auth_client.post(
        "/auth/login",
        json={"email": "ADMIN@example.test", "password": "correct-password"},
    )

    assert response.status_code == 200
    assert response.json()["user"]["email"] == "admin@example.test"
    assert response.json()["user"]["display_name"] == "Admin User"
    assert response.json()["user"]["role"] == "Admin"
    assert "users:manage" in response.json()["user"]["permissions"]
    set_cookie_headers = response.headers.get_list("set-cookie")
    assert any(
        "eve_access_token=" in header and "HttpOnly" in header
        for header in set_cookie_headers
    )
    assert any(
        "eve_refresh_token=" in header and "HttpOnly" in header for header in set_cookie_headers
    )
    assert "eve_access_token" in auth_client.cookies
    assert "eve_refresh_token" in auth_client.cookies
    assert "eve_csrf_token" in auth_client.cookies


@pytest.mark.asyncio
async def test_sso_status_reports_unavailable_until_oidc_is_configured() -> None:
    """The public SSO status endpoint only enables login for usable OIDC settings."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    client = TestClient(
        create_app(
            settings=Settings(auth_secret_key="test-signing-key", cookie_secure=False),  # noqa: S106
            sessionmaker=sessionmaker,
        )
    )

    missing = client.get("/auth/sso/status")

    assert missing.status_code == 200
    assert missing.json() == {
        "enabled": False,
        "provider": "oidc",
        "display_name": "",
        "login_url": None,
    }

    async with sessionmaker() as session:
        session.add(
            SsoConfiguration(
                id="default",
                enabled=True,
                provider="oidc",
                display_name="Corporate IdP",
                issuer_url="https://idp.example.test",
                client_id="eve-client",
            )
        )
        await session.commit()

    configured = client.get("/auth/sso/status")

    assert configured.status_code == 200
    assert configured.json() == {
        "enabled": True,
        "provider": "oidc",
        "display_name": "Corporate IdP",
        "login_url": "http://localhost:8001/auth/sso/login",
    }
    await sessionmaker.kw["bind"].dispose()


@pytest.mark.asyncio
async def test_sso_login_rejects_disabled_configuration() -> None:
    """Browser SSO login cannot start until SSO is explicitly enabled."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    client = TestClient(
        create_app(
            settings=Settings(auth_secret_key="test-signing-key", cookie_secure=False),  # noqa: S106
            sessionmaker=sessionmaker,
        )
    )

    response = client.get("/auth/sso/login", follow_redirects=False)

    assert response.status_code == 400
    assert response.json() == {"detail": "SSO is not enabled"}
    await sessionmaker.kw["bind"].dispose()


@pytest.mark.asyncio
async def test_sso_login_redirects_to_oidc_authorization_endpoint() -> None:
    """OIDC SSO login redirects to the configured identity provider."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with sessionmaker() as session:
        session.add(
            SsoConfiguration(
                id="default",
                enabled=True,
                provider="oidc",
                display_name="Corporate IdP",
                issuer_url="https://idp.example.test",
                client_id="eve-client",
            )
        )
        await session.commit()

    client = TestClient(
        create_app(
            settings=Settings(
                auth_secret_key="test-signing-key",  # noqa: S106
                cookie_secure=False,
                api_base_url="http://localhost:8001",
            ),
            sessionmaker=sessionmaker,
        )
    )

    response = client.get("/auth/sso/login", follow_redirects=False)

    assert response.status_code == 307
    location = response.headers["location"]
    parsed = urlparse(location)
    query = parse_qs(parsed.query)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == "https://idp.example.test/authorize"
    assert query["response_type"] == ["code"]
    assert query["client_id"] == ["eve-client"]
    assert query["redirect_uri"] == ["http://localhost:8001/auth/sso/oidc/callback"]
    assert query["scope"] == ["openid email profile"]
    assert query["state"][0]
    assert query["nonce"][0]
    set_cookie_headers = response.headers.get_list("set-cookie")
    assert any("eve_sso_state=" in header and "HttpOnly" in header for header in set_cookie_headers)
    assert any("eve_sso_nonce=" in header and "HttpOnly" in header for header in set_cookie_headers)
    await sessionmaker.kw["bind"].dispose()


@pytest.mark.asyncio
async def test_oidc_callback_validates_state_before_token_exchange() -> None:
    """OIDC callbacks must present the browser-bound state token."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    client = TestClient(
        create_app(
            settings=Settings(auth_secret_key="test-signing-key", cookie_secure=False),  # noqa: S106
            sessionmaker=sessionmaker,
        )
    )
    client.cookies.set("eve_sso_state", "expected-state")

    response = client.get("/auth/sso/oidc/callback?code=abc123&state=wrong-state")

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid SSO state"}
    await sessionmaker.kw["bind"].dispose()


@pytest.mark.asyncio
async def test_oidc_callback_exchanges_code_and_auto_provisions_user(monkeypatch) -> None:
    """A valid OIDC callback can create a local user and issue browser cookies."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with sessionmaker() as session:
        role = Role(id=uuid4(), name="Analyst", is_system_role=True, permissions=["findings:read"])
        session.add_all(
            [
                role,
                SsoConfiguration(
                    id="default",
                    enabled=True,
                    provider="oidc",
                    display_name="Corporate IdP",
                    issuer_url="https://idp.example.test",
                    client_id="eve-client",
                    auto_provision=True,
                    default_role="Analyst",
                ),
            ]
        )
        await session.commit()

    id_token, public_jwk = _signed_oidc_token()

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self) -> FakeAsyncClient:
            return self

        async def __aexit__(self, *args) -> None:
            return None

        async def post(self, url: str, data: dict[str, str], **kwargs) -> HttpxResponse:
            assert url == "https://idp.example.test/token"
            assert data["grant_type"] == "authorization_code"
            assert data["code"] == "auth-code"
            assert data["client_id"] == "eve-client"
            assert data["redirect_uri"] == "http://localhost:8001/auth/sso/oidc/callback"
            return HttpxResponse(
                200,
                json={"access_token": "provider-access-token", "id_token": id_token},
            )

        async def get(
            self,
            url: str,
            headers: dict[str, str] | None = None,
            **kwargs,
        ) -> HttpxResponse:
            if url.endswith("/.well-known/openid-configuration"):
                return HttpxResponse(
                    200,
                    json={
                        "issuer": "https://idp.example.test",
                        "token_endpoint": "https://idp.example.test/token",
                        "userinfo_endpoint": "https://idp.example.test/userinfo",
                        "jwks_uri": "https://idp.example.test/jwks",
                    },
                )
            if url.endswith("/jwks"):
                return HttpxResponse(200, json={"keys": [public_jwk]})
            assert url == "https://idp.example.test/userinfo"
            assert headers is not None
            assert headers["Authorization"] == "Bearer provider-access-token"
            return HttpxResponse(
                200,
                json={
                    "sub": "user-123",
                    "email": "New.User@Example.Test",
                    "email_verified": True,
                    "name": "New User",
                },
            )

    monkeypatch.setattr("app.routers.auth.httpx.AsyncClient", FakeAsyncClient)

    client = TestClient(
        create_app(
            settings=Settings(
                auth_secret_key="test-signing-key",  # noqa: S106
                cookie_secure=False,
                api_base_url="http://localhost:8001",
            ),
            sessionmaker=sessionmaker,
        )
    )
    client.cookies.set("eve_sso_state", "expected-state")
    client.cookies.set("eve_sso_nonce", "expected-nonce")

    response = client.get("/auth/sso/oidc/callback?code=auth-code&state=expected-state")

    assert response.status_code == 200
    assert response.json()["user"]["email"] == "new.user@example.test"
    assert response.json()["user"]["display_name"] == "New User"
    assert response.json()["user"]["role"] == "Analyst"
    assert "eve_access_token" in client.cookies
    assert "eve_refresh_token" in client.cookies

    async with sessionmaker() as session:
        result = await session.execute(select(User).where(User.email == "new.user@example.test"))
        stored_user = result.scalar_one_or_none()
        assert stored_user is not None
        assert stored_user.display_name == "New User"
        assert stored_user.role_id == role.id

    await sessionmaker.kw["bind"].dispose()


@pytest.mark.asyncio
async def test_oidc_callback_validates_id_token_with_discovery_jwks_and_nonce(
    monkeypatch,
) -> None:
    """OIDC login validates the signed ID token before trusting provider identity."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with sessionmaker() as session:
        role = Role(id=uuid4(), name="Analyst", is_system_role=True, permissions=["findings:read"])
        session.add_all(
            [
                role,
                SsoConfiguration(
                    id="default",
                    enabled=True,
                    provider="oidc",
                    issuer_url="https://idp.example.test",
                    client_id="eve-client",
                    auto_provision=True,
                    default_role="Analyst",
                ),
            ]
        )
        await session.commit()

    id_token, public_jwk = _signed_oidc_token()
    calls: list[tuple[str, str]] = []

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self) -> FakeAsyncClient:
            return self

        async def __aexit__(self, *args) -> None:
            return None

        async def post(self, url: str, *args, **kwargs) -> HttpxResponse:
            calls.append(("POST", url))
            return HttpxResponse(
                200,
                json={"access_token": "provider-access-token", "id_token": id_token},
            )

        async def get(self, url: str, *args, **kwargs) -> HttpxResponse:
            calls.append(("GET", url))
            if url.endswith("/.well-known/openid-configuration"):
                return HttpxResponse(
                    200,
                    json={
                        "issuer": "https://idp.example.test",
                        "token_endpoint": "https://idp.example.test/oauth/token",
                        "userinfo_endpoint": "https://idp.example.test/oauth/userinfo",
                        "jwks_uri": "https://idp.example.test/oauth/jwks",
                    },
                )
            if url.endswith("/oauth/jwks"):
                return HttpxResponse(200, json={"keys": [public_jwk]})
            if url.endswith("/oauth/userinfo"):
                return HttpxResponse(
                    200,
                    json={
                        "sub": "user-123",
                        "email": "new.user@example.test",
                        "email_verified": True,
                        "name": "New User",
                    },
                )
            raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr("app.routers.auth.httpx.AsyncClient", FakeAsyncClient)

    client = TestClient(
        create_app(
            settings=Settings(
                auth_secret_key="test-signing-key",  # noqa: S106
                cookie_secure=False,
                api_base_url="http://localhost:8001",
            ),
            sessionmaker=sessionmaker,
        )
    )
    client.cookies.set("eve_sso_state", "expected-state")
    client.cookies.set("eve_sso_nonce", "expected-nonce")

    response = client.get("/auth/sso/oidc/callback?code=auth-code&state=expected-state")

    assert response.status_code == 200
    assert response.json()["user"]["email"] == "new.user@example.test"
    assert ("GET", "https://idp.example.test/.well-known/openid-configuration") in calls
    assert ("POST", "https://idp.example.test/oauth/token") in calls
    assert ("GET", "https://idp.example.test/oauth/jwks") in calls
    assert ("GET", "https://idp.example.test/oauth/userinfo") in calls
    await sessionmaker.kw["bind"].dispose()


@pytest.mark.asyncio
async def test_oidc_callback_rejects_id_token_with_wrong_nonce(monkeypatch) -> None:
    """The ID token nonce must match the nonce bound to the browser login attempt."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with sessionmaker() as session:
        session.add(
            SsoConfiguration(
                id="default",
                enabled=True,
                provider="oidc",
                issuer_url="https://idp.example.test",
                client_id="eve-client",
            )
        )
        await session.commit()

    id_token, public_jwk = _signed_oidc_token(nonce="wrong-nonce")

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self) -> FakeAsyncClient:
            return self

        async def __aexit__(self, *args) -> None:
            return None

        async def post(self, *args, **kwargs) -> HttpxResponse:
            return HttpxResponse(
                200,
                json={"access_token": "provider-access-token", "id_token": id_token},
            )

        async def get(self, url: str, *args, **kwargs) -> HttpxResponse:
            if url.endswith("/.well-known/openid-configuration"):
                return HttpxResponse(
                    200,
                    json={
                        "issuer": "https://idp.example.test",
                        "token_endpoint": "https://idp.example.test/token",
                        "userinfo_endpoint": "https://idp.example.test/userinfo",
                        "jwks_uri": "https://idp.example.test/jwks",
                    },
                )
            if url.endswith("/jwks"):
                return HttpxResponse(200, json={"keys": [public_jwk]})
            return HttpxResponse(200, json={"email": "new.user@example.test"})

    monkeypatch.setattr("app.routers.auth.httpx.AsyncClient", FakeAsyncClient)

    client = TestClient(
        create_app(
            settings=Settings(auth_secret_key="test-signing-key", cookie_secure=False),  # noqa: S106
            sessionmaker=sessionmaker,
        )
    )
    client.cookies.set("eve_sso_state", "expected-state")
    client.cookies.set("eve_sso_nonce", "expected-nonce")

    response = client.get("/auth/sso/oidc/callback?code=auth-code&state=expected-state")

    assert response.status_code == 401
    assert response.json() == {"detail": "SSO ID token is invalid"}
    assert "eve_access_token" not in client.cookies
    await sessionmaker.kw["bind"].dispose()


@pytest.mark.asyncio
async def test_oidc_callback_rejects_unknown_user_when_auto_provisioning_is_disabled(
    monkeypatch,
) -> None:
    """Unknown OIDC users require auto-provisioning to be enabled."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with sessionmaker() as session:
        role = Role(id=uuid4(), name="Analyst", is_system_role=True, permissions=["findings:read"])
        session.add_all(
            [
                role,
                SsoConfiguration(
                    id="default",
                    enabled=True,
                    provider="oidc",
                    issuer_url="https://idp.example.test",
                    client_id="eve-client",
                    auto_provision=False,
                    default_role="Analyst",
                ),
            ]
        )
        await session.commit()

    id_token, public_jwk = _signed_oidc_token()

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self) -> FakeAsyncClient:
            return self

        async def __aexit__(self, *args) -> None:
            return None

        async def post(self, *args, **kwargs) -> HttpxResponse:
            return HttpxResponse(
                200,
                json={"access_token": "provider-access-token", "id_token": id_token},
            )

        async def get(self, url: str, *args, **kwargs) -> HttpxResponse:
            if url.endswith("/.well-known/openid-configuration"):
                return HttpxResponse(
                    200,
                    json={
                        "issuer": "https://idp.example.test",
                        "token_endpoint": "https://idp.example.test/token",
                        "userinfo_endpoint": "https://idp.example.test/userinfo",
                        "jwks_uri": "https://idp.example.test/jwks",
                    },
                )
            if url.endswith("/jwks"):
                return HttpxResponse(200, json={"keys": [public_jwk]})
            return HttpxResponse(
                200,
                json={"email": "missing@example.test", "email_verified": True},
            )

    monkeypatch.setattr("app.routers.auth.httpx.AsyncClient", FakeAsyncClient)

    client = TestClient(
        create_app(
            settings=Settings(auth_secret_key="test-signing-key", cookie_secure=False),  # noqa: S106
            sessionmaker=sessionmaker,
        )
    )
    client.cookies.set("eve_sso_state", "expected-state")
    client.cookies.set("eve_sso_nonce", "expected-nonce")

    response = client.get("/auth/sso/oidc/callback?code=auth-code&state=expected-state")

    assert response.status_code == 403
    assert response.json() == {"detail": "SSO user is not provisioned"}
    await sessionmaker.kw["bind"].dispose()


@pytest.mark.asyncio
async def test_saml_metadata_endpoint_returns_sp_metadata_when_saml_enabled() -> None:
    """SAML configurations expose service-provider metadata for IdP setup."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with sessionmaker() as session:
        session.add(
            SsoConfiguration(
                id="default",
                enabled=True,
                provider="saml",
                display_name="Corporate SAML",
                issuer_url="https://idp.example.test/sso",
                client_id="eve-saml-sp",
            )
        )
        await session.commit()

    client = TestClient(
        create_app(
            settings=Settings(
                auth_secret_key="test-signing-key",  # noqa: S106
                cookie_secure=False,
                api_base_url="http://localhost:8001",
            ),
            sessionmaker=sessionmaker,
        )
    )

    response = client.get("/auth/sso/saml/metadata")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/samlmetadata+xml")
    assert 'entityID="http://localhost:8001/auth/sso/saml/metadata"' in response.text
    assert 'Location="http://localhost:8001/auth/sso/saml/acs"' in response.text
    await sessionmaker.kw["bind"].dispose()


@pytest.mark.asyncio
async def test_saml_acs_returns_not_implemented_until_assertion_validation_exists() -> None:
    """SAML ACS is explicit about the remaining validation implementation."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    client = TestClient(
        create_app(
            settings=Settings(auth_secret_key="test-signing-key", cookie_secure=False),  # noqa: S106
            sessionmaker=sessionmaker,
        )
    )

    response = client.post("/auth/sso/saml/acs", data={"SAMLResponse": "placeholder"})

    assert response.status_code == 501
    assert response.json() == {"detail": "SAML assertion validation is not implemented yet"}
    await sessionmaker.kw["bind"].dispose()


def test_me_returns_current_user_from_access_cookie(auth_client: TestClient) -> None:
    """Authenticated requests can resolve the current local user."""
    auth_client.post(
        "/auth/login",
        json={"email": "admin@example.test", "password": "correct-password"},
    )

    response = auth_client.get("/auth/me")

    assert response.status_code == 200
    assert response.json()["email"] == "admin@example.test"
    assert response.json()["role"] == "Admin"
    assert "users:manage" in response.json()["permissions"]


def test_admin_role_receives_builtin_permissions_even_if_database_role_is_stale() -> None:
    """The built-in Admin role remains authorized if an older DB row has stale permissions."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")

    async def seed() -> None:
        async with sessionmaker.kw["bind"].begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        async with sessionmaker() as session:
            role = Role(id=uuid4(), name="Admin", is_system_role=True, permissions=[])
            user = User(
                id=uuid4(),
                email="admin@example.test",
                display_name="Admin User",
                role_id=role.id,
                password_hash=PasswordHasher().hash_password("correct-password"),
            )
            session.add_all([role, user])
            await session.commit()

    anyio.run(seed)
    client = TestClient(
        create_app(
            settings=Settings(auth_secret_key="test-signing-key", cookie_secure=False),  # noqa: S106
            sessionmaker=sessionmaker,
        )
    )
    login = client.post(
        "/auth/login",
        json={"email": "admin@example.test", "password": "correct-password"},
    )
    users = client.get("/admin/users")

    assert login.status_code == 200
    assert "users:manage" in login.json()["user"]["permissions"]
    assert users.status_code == 200
    anyio.run(sessionmaker.kw["bind"].dispose)


@pytest.mark.asyncio
async def test_disabled_account_login_returns_specific_error() -> None:
    """Disabled users receive a distinct login error for the UI."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with sessionmaker() as session:
        role = Role(id=uuid4(), name="Admin", is_system_role=True, permissions=["*"])
        user = User(
            id=uuid4(),
            email="disabled@example.test",
            display_name="Disabled User",
            role_id=role.id,
            password_hash=PasswordHasher().hash_password("correct-password"),
            disabled_at=datetime.now(UTC),
        )
        session.add_all([role, user])
        await session.commit()

    client = TestClient(
        create_app(
            settings=Settings(auth_secret_key="test-key"),  # noqa: S106
            sessionmaker=sessionmaker,
        )
    )
    response = client.post(
        "/auth/login",
        json={"email": "disabled@example.test", "password": "correct-password"},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Account is disabled"}
    await sessionmaker.kw["bind"].dispose()


@pytest.mark.asyncio
async def test_mfa_enabled_user_must_verify_code_before_session_is_issued() -> None:
    """MFA-enabled users complete login only after TOTP verification."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    secret = "JBSWY3DPEHPK3PXP"  # noqa: S105
    async with sessionmaker() as session:
        role = Role(id=uuid4(), name="Admin", is_system_role=True, permissions=["*"])
        user = User(
            id=uuid4(),
            email="admin@example.test",
            display_name="Admin User",
            role_id=role.id,
            password_hash=PasswordHasher().hash_password("correct-password"),
            mfa_enrolled=True,
            mfa_secret=secret,
        )
        session.add_all([role, user])
        await session.commit()

    client = TestClient(
        create_app(
            settings=Settings(auth_secret_key="test-signing-key", cookie_secure=False),  # noqa: S106
            sessionmaker=sessionmaker,
        )
    )
    login = client.post(
        "/auth/login",
        json={"email": "admin@example.test", "password": "correct-password"},
    )

    assert login.status_code == 202
    assert login.json()["mfa_required"] is True
    assert "mfa_challenge_token" in login.json()
    assert "eve_access_token" not in client.cookies

    rejected = client.post(
        "/auth/mfa/verify",
        json={"mfa_challenge_token": login.json()["mfa_challenge_token"], "code": "000000"},
    )
    verified = client.post(
        "/auth/mfa/verify",
        json={
            "mfa_challenge_token": login.json()["mfa_challenge_token"],
            "code": generate_totp_code(secret),
        },
    )

    assert rejected.status_code == 401
    assert rejected.json() == {"detail": "Invalid MFA code"}
    assert verified.status_code == 200
    assert verified.json()["user"]["email"] == "admin@example.test"
    assert "eve_access_token" in client.cookies
    await sessionmaker.kw["bind"].dispose()


def test_me_requires_valid_access_cookie(auth_client: TestClient) -> None:
    """Missing auth cookies are rejected."""
    response = auth_client.get("/auth/me")

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


def test_refresh_rotates_refresh_session(auth_client: TestClient) -> None:
    """Refreshing issues new cookies and revokes the old refresh session."""
    auth_client.post(
        "/auth/login",
        json={"email": "admin@example.test", "password": "correct-password"},
    )
    original_refresh = auth_client.cookies["eve_refresh_token"]

    response = auth_client.post("/auth/refresh", headers=_csrf_headers(auth_client))

    assert response.status_code == 200
    assert auth_client.cookies["eve_refresh_token"] != original_refresh


def test_refresh_requires_csrf_header(auth_client: TestClient) -> None:
    """Refresh rejects cookie-authenticated requests without CSRF proof."""
    auth_client.post(
        "/auth/login",
        json={"email": "admin@example.test", "password": "correct-password"},
    )

    response = auth_client.post("/auth/refresh")

    assert response.status_code == 403
    assert response.json() == {"detail": "CSRF validation failed"}


def test_logout_revokes_refresh_session_and_clears_cookies(auth_client: TestClient) -> None:
    """Logout revokes the active refresh session and clears browser cookies."""
    auth_client.post(
        "/auth/login",
        json={"email": "admin@example.test", "password": "correct-password"},
    )

    response = auth_client.post("/auth/logout", headers=_csrf_headers(auth_client))

    assert response.status_code == 204
    assert "eve_access_token" not in auth_client.cookies
    assert "eve_refresh_token" not in auth_client.cookies
    assert "eve_csrf_token" not in auth_client.cookies


def test_logout_requires_csrf_header(auth_client: TestClient) -> None:
    """Logout rejects cookie-authenticated requests without CSRF proof."""
    auth_client.post(
        "/auth/login",
        json={"email": "admin@example.test", "password": "correct-password"},
    )

    response = auth_client.post("/auth/logout")

    assert response.status_code == 403
    assert response.json() == {"detail": "CSRF validation failed"}


@pytest.mark.asyncio
async def test_expired_refresh_sessions_are_rejected() -> None:
    """Refresh attempts cannot use expired persisted refresh sessions."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    signing_key = "test-signing-key"
    settings = Settings(auth_secret_key=signing_key)
    client = TestClient(create_app(settings=settings, sessionmaker=sessionmaker))

    async with sessionmaker() as session:
        role = Role(id=uuid4(), name="Admin", is_system_role=True, permissions=["*"])
        user = User(
            id=uuid4(),
            email="admin@example.test",
            display_name="Admin User",
            role_id=role.id,
            password_hash=PasswordHasher().hash_password("correct-password"),
        )
        plaintext_refresh = "expired-token"
        stored_hash = RefreshSessionService.hash_refresh_token(plaintext_refresh)
        expired = RefreshSession(
            user_id=user.id,
            refresh_token_hash=stored_hash,
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )
        session.add_all([role, user, expired])
        await session.commit()

    client.cookies.set("eve_refresh_token", plaintext_refresh)
    client.cookies.set("eve_csrf_token", "known-csrf-token")
    response = client.post("/auth/refresh", headers={"x-csrf-token": "known-csrf-token"})

    assert response.status_code == 401
    assert response.json() == {"detail": "Refresh session expired or revoked"}

    await sessionmaker.kw["bind"].dispose()
