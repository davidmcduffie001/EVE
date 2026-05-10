"""Request-level tests for authentication endpoints."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.database import create_sessionmaker
from app.main import create_app
from app.models.base import Base, RefreshSession, Role, User
from app.services.auth.mfa import generate_totp_code
from app.services.auth.security import PasswordHasher
from app.services.auth.sessions import RefreshSessionService


def _csrf_headers(client: TestClient) -> dict[str, str]:
    return {"x-csrf-token": client.cookies["eve_csrf_token"]}


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
    assert response.json()["user"] == {
        "id": response.json()["user"]["id"],
        "email": "admin@example.test",
        "display_name": "Admin User",
        "role": "Admin",
        "permissions": ["*"],
    }
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
    assert response.json()["permissions"] == ["*"]


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
