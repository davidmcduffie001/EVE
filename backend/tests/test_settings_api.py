"""Request-level tests for user settings endpoints."""

from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import anyio
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.database import create_sessionmaker
from app.main import create_app
from app.models.base import Base, RefreshSession, Role, User, UserPreference
from app.routers.settings import _get_or_create_preferences
from app.services.auth.mfa import generate_totp_code
from app.services.auth.security import PasswordHasher
from app.services.auth.sessions import RefreshSessionService


def _csrf_headers(client: TestClient) -> dict[str, str]:
    return {"x-csrf-token": client.cookies["eve_csrf_token"]}


@pytest.fixture
def settings_app() -> tuple[FastAPI, async_sessionmaker[AsyncSession]]:
    """Create a test app with admin and analyst users."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")

    async def seed() -> None:
        async with sessionmaker.kw["bind"].begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        async with sessionmaker() as session:
            role = Role(
                id=uuid4(),
                name="Admin",
                is_system_role=True,
                permissions=["users:manage", "audit:read"],
            )
            users = [
                User(
                    id=uuid4(),
                    email="admin@example.test",
                    display_name="Admin User",
                    role_id=role.id,
                    password_hash=PasswordHasher().hash_password("correct-password"),
                ),
                User(
                    id=uuid4(),
                    email="other@example.test",
                    display_name="Other User",
                    role_id=role.id,
                    password_hash=PasswordHasher().hash_password("correct-password"),
                ),
            ]
            session.add_all([role, *users])
            await session.commit()

    anyio.run(seed)
    app = create_app(
        settings=Settings(auth_secret_key="test-signing-key", cookie_secure=False),  # noqa: S106
        sessionmaker=sessionmaker,
    )
    yield app, sessionmaker
    anyio.run(sessionmaker.kw["bind"].dispose)


def _login(client: TestClient, *, password: str = "correct-password") -> None:  # noqa: S107
    response = client.post(
        "/auth/login",
        json={"email": "admin@example.test", "password": password},
    )
    assert response.status_code == 200


def test_profile_endpoint_returns_current_user_settings(
    settings_app: tuple[FastAPI, async_sessionmaker[AsyncSession]],
) -> None:
    """Authenticated users can read their account profile."""
    app, _sessionmaker = settings_app
    with TestClient(app) as client:
        _login(client)

        response = client.get("/settings/profile")

    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "admin@example.test"
    assert body["display_name"] == "Admin User"
    assert body["role"] == "Admin"
    assert body["mfa_enrolled"] is False


def test_profile_update_changes_display_name_without_password_confirmation(
    settings_app: tuple[FastAPI, async_sessionmaker[AsyncSession]],
) -> None:
    """Display-name changes do not require password re-authentication."""
    app, _sessionmaker = settings_app
    with TestClient(app) as client:
        _login(client)

        response = client.patch(
            "/settings/profile",
            json={"display_name": "Updated Admin"},
            headers=_csrf_headers(client),
        )

    assert response.status_code == 200
    assert response.json()["display_name"] == "Updated Admin"


def test_email_update_requires_current_password(
    settings_app: tuple[FastAPI, async_sessionmaker[AsyncSession]],
) -> None:
    """Email changes require the current password."""
    app, _sessionmaker = settings_app
    with TestClient(app) as client:
        _login(client)

        response = client.patch(
            "/settings/profile",
            json={"email": "new-admin@example.test"},
            headers=_csrf_headers(client),
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "Current password is required to change email"}


def test_email_update_rejects_duplicate_email(
    settings_app: tuple[FastAPI, async_sessionmaker[AsyncSession]],
) -> None:
    """Email changes cannot collide with another user account."""
    app, _sessionmaker = settings_app
    with TestClient(app) as client:
        _login(client)

        response = client.patch(
            "/settings/profile",
            json={"email": "other@example.test", "current_password": "correct-password"},
            headers=_csrf_headers(client),
        )

    assert response.status_code == 409
    assert response.json() == {"detail": "Email is already in use"}


def test_password_update_changes_password_and_revokes_other_sessions(
    settings_app: tuple[FastAPI, async_sessionmaker[AsyncSession]],
) -> None:
    """Password changes verify the old password and revoke other refresh sessions."""
    app, sessionmaker = settings_app
    with TestClient(app) as first_client, TestClient(app) as second_client:
        _login(first_client)
        _login(second_client)
        first_refresh = first_client.cookies["eve_refresh_token"]
        second_refresh = second_client.cookies["eve_refresh_token"]

        response = first_client.put(
            "/settings/password",
            json={
                "current_password": "correct-password",
                "new_password": "new-correct-password",
            },
            headers=_csrf_headers(first_client),
        )

        old_login = second_client.post(
            "/auth/login",
            json={"email": "admin@example.test", "password": "correct-password"},
        )
        new_login = second_client.post(
            "/auth/login",
            json={"email": "admin@example.test", "password": "new-correct-password"},
        )

    async def fetch_sessions() -> dict[str, RefreshSession | None]:
        async with sessionmaker() as session:
            first = await session.scalar(
                select(RefreshSession).where(
                    RefreshSession.refresh_token_hash
                    == RefreshSessionService.hash_refresh_token(first_refresh)
                )
            )
            second = await session.scalar(
                select(RefreshSession).where(
                    RefreshSession.refresh_token_hash
                    == RefreshSessionService.hash_refresh_token(second_refresh)
                )
            )
            return {"first": first, "second": second}

    sessions = anyio.run(fetch_sessions)
    assert response.status_code == 204
    assert old_login.status_code == 401
    assert new_login.status_code == 200
    assert sessions["first"] is not None
    assert sessions["first"].revoked_at is None
    assert sessions["second"] is not None
    assert sessions["second"].revoked_at is not None


def test_mfa_enrollment_verifies_totp_code(
    settings_app: tuple[FastAPI, async_sessionmaker[AsyncSession]],
) -> None:
    """Users can enroll MFA by verifying a generated TOTP secret."""
    app, sessionmaker = settings_app
    with TestClient(app) as client:
        _login(client)

        enrollment = client.post("/settings/mfa/enrollment", headers=_csrf_headers(client))
        secret = enrollment.json()["secret"]
        verify = client.post(
            "/settings/mfa/verify",
            json={"code": generate_totp_code(secret)},
            headers=_csrf_headers(client),
        )
        profile = client.get("/settings/profile")

    async def fetch_user() -> User | None:
        async with sessionmaker() as session:
            return await session.scalar(select(User).where(User.email == "admin@example.test"))

    stored_user = anyio.run(fetch_user)
    assert enrollment.status_code == 201
    assert enrollment.json()["otpauth_uri"].startswith("otpauth://totp/EVE%3A")
    assert "algorithm=SHA256" in enrollment.json()["otpauth_uri"]
    assert verify.status_code == 200
    assert verify.json()["mfa_enrolled"] is True
    assert profile.json()["mfa_enrolled"] is True
    assert stored_user is not None
    assert stored_user.mfa_enrolled is True
    assert stored_user.mfa_secret == secret


def test_mfa_verify_rejects_invalid_code(
    settings_app: tuple[FastAPI, async_sessionmaker[AsyncSession]],
) -> None:
    """Enrollment remains pending when the TOTP code is invalid."""
    app, _sessionmaker = settings_app
    with TestClient(app) as client:
        _login(client)
        client.post("/settings/mfa/enrollment", headers=_csrf_headers(client))

        response = client.post(
            "/settings/mfa/verify",
            json={"code": "000000"},
            headers=_csrf_headers(client),
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid MFA code"}


def test_mfa_disable_requires_current_password(
    settings_app: tuple[FastAPI, async_sessionmaker[AsyncSession]],
) -> None:
    """Disabling MFA requires the current password and clears the stored secret."""
    app, sessionmaker = settings_app
    with TestClient(app) as client:
        _login(client)
        enrollment = client.post("/settings/mfa/enrollment", headers=_csrf_headers(client))
        client.post(
            "/settings/mfa/verify",
            json={"code": generate_totp_code(enrollment.json()["secret"])},
            headers=_csrf_headers(client),
        )

        rejected = client.post(
            "/settings/mfa/disable",
            json={"current_password": "wrong-password"},
            headers=_csrf_headers(client),
        )
        disabled = client.post(
            "/settings/mfa/disable",
            json={"current_password": "correct-password"},
            headers=_csrf_headers(client),
        )

    async def fetch_user() -> User | None:
        async with sessionmaker() as session:
            return await session.scalar(select(User).where(User.email == "admin@example.test"))

    stored_user = anyio.run(fetch_user)
    assert rejected.status_code == 403
    assert disabled.status_code == 200
    assert disabled.json()["mfa_enrolled"] is False
    assert stored_user is not None
    assert stored_user.mfa_enrolled is False
    assert stored_user.mfa_secret is None


def test_preferences_round_trip(
    settings_app: tuple[FastAPI, async_sessionmaker[AsyncSession]],
) -> None:
    """Users can persist their display and table preferences."""
    app, _sessionmaker = settings_app
    with TestClient(app) as client:
        _login(client)

        update = client.put(
            "/settings/preferences",
            json={
                "theme_preference": "light",
                "timezone": "America/Denver",
                "date_format": "MM/DD/YYYY",
                "default_landing_page": "findings",
                "table_state": {"findings": {"page_size": 100}},
            },
            headers=_csrf_headers(client),
        )
        read = client.get("/settings/preferences")

    assert update.status_code == 200
    assert read.status_code == 200
    assert read.json() == {
        "theme_preference": "light",
        "timezone": "America/Denver",
        "date_format": "MM/DD/YYYY",
        "default_landing_page": "findings",
        "table_state": {"findings": {"page_size": 100}},
    }


def test_concurrent_initial_preference_reads_share_one_row(
    settings_app: tuple[FastAPI, async_sessionmaker[AsyncSession]],
) -> None:
    """Duplicate first-time preference reads should not race into a 500."""
    app, _sessionmaker = settings_app

    def read_preferences() -> int:
        with TestClient(app) as client:
            _login(client)
            return client.get("/settings/preferences").status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(lambda _index: read_preferences(), range(2)))

    assert statuses == [200, 200]


def test_preference_creation_rechecks_for_existing_row_before_insert() -> None:
    """Preference creation re-reads before inserting while guarded by the caller lock."""
    user = User(id=uuid4(), email="admin@example.test", display_name="Admin User", role_id=uuid4())
    existing_preferences = UserPreference(user_id=user.id, timezone="UTC")

    class RacingPreferenceSession:
        def __init__(self) -> None:
            self.add_called = False
            self.get_calls = 0

        async def get(self, _model: type[UserPreference], _key: object) -> UserPreference | None:
            self.get_calls += 1
            return None if self.get_calls == 1 else existing_preferences

        def add(self, _preferences: UserPreference) -> None:
            self.add_called = True
            return None

        async def flush(self) -> None:
            raise AssertionError("flush should not run when the second read finds preferences")

    session = RacingPreferenceSession()

    preferences = anyio.run(_get_or_create_preferences, session, user)

    assert preferences is existing_preferences
    assert session.add_called is False
