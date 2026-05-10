"""Authentication API routes."""

from __future__ import annotations

import hmac
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Response, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.database import get_db_session
from app.models.base import Role, User
from app.services.auth.security import InvalidTokenError, PasswordHasher, TokenSigner
from app.services.auth.sessions import RefreshSessionService


class LoginRequest(BaseModel):
    """Login request body."""

    email: str
    password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        """Normalize local-account email lookup keys."""
        return value.strip().lower()


class UserResponse(BaseModel):
    """Authenticated user details returned to browser clients."""

    id: UUID
    email: str
    display_name: str
    role: str


class AuthResponse(BaseModel):
    """Authentication response body."""

    user: UserResponse
    access_expires_at: datetime


def create_auth_router(
    settings: Settings,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> APIRouter:
    """Create the auth router with concrete runtime dependencies."""
    router = APIRouter(prefix="/auth", tags=["Authentication"])
    db_dependency = get_db_session(sessionmaker)
    db_session = Depends(db_dependency)
    password_hasher = PasswordHasher()
    token_signer = TokenSigner(settings)

    async def current_user(
        access_token: str | None = Cookie(default=None, alias=settings.access_cookie_name),
        session: AsyncSession = db_session,
    ) -> UserResponse:
        if access_token is None:
            raise _auth_required()

        try:
            claims = token_signer.verify_access_token(access_token)
            user_id = UUID(claims.subject)
        except (InvalidTokenError, ValueError):
            raise _auth_required() from None

        user_with_role = await _fetch_user_with_role(session, user_id=user_id)
        if user_with_role is None:
            raise _auth_required()

        user, role = user_with_role
        return _serialize_user(user, role)

    @router.post("/login", response_model=AuthResponse)
    async def login(
        request: LoginRequest,
        response: Response,
        session: AsyncSession = db_session,
    ) -> AuthResponse:
        """Authenticate local credentials and set browser session cookies."""
        user_with_role = await _fetch_user_with_role(session, email=request.email)
        if user_with_role is None:
            raise _invalid_credentials()

        user, role = user_with_role
        if not password_hasher.verify_password(request.password, user.password_hash):
            raise _invalid_credentials()

        return await _issue_browser_session(
            response=response,
            session=session,
            settings=settings,
            token_signer=token_signer,
            user=user,
            role=role,
        )

    @router.post("/refresh", response_model=AuthResponse)
    async def refresh(
        response: Response,
        refresh_token: str | None = Cookie(default=None, alias=settings.refresh_cookie_name),
        csrf_cookie: str | None = Cookie(default=None, alias=settings.csrf_cookie_name),
        csrf_header: str | None = Header(default=None, alias=settings.csrf_header_name),
        session: AsyncSession = db_session,
    ) -> AuthResponse:
        """Rotate a valid refresh session and issue fresh browser cookies."""
        _validate_csrf(csrf_cookie=csrf_cookie, csrf_header=csrf_header)
        if refresh_token is None:
            raise _refresh_required()

        refresh_service = RefreshSessionService(session)
        active_session = await refresh_service.get_active_session(refresh_token)
        if active_session is None:
            raise _refresh_required()

        user_with_role = await _fetch_user_with_role(session, user_id=active_session.user_id)
        if user_with_role is None:
            await refresh_service.revoke_session(refresh_token)
            await session.commit()
            raise _refresh_required()

        await refresh_service.revoke_session(refresh_token)
        user, role = user_with_role
        return await _issue_browser_session(
            response=response,
            session=session,
            settings=settings,
            token_signer=token_signer,
            user=user,
            role=role,
        )

    @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
    async def logout(
        response: Response,
        refresh_token: str | None = Cookie(default=None, alias=settings.refresh_cookie_name),
        csrf_cookie: str | None = Cookie(default=None, alias=settings.csrf_cookie_name),
        csrf_header: str | None = Header(default=None, alias=settings.csrf_header_name),
        session: AsyncSession = db_session,
    ) -> Response:
        """Revoke the active refresh session and clear browser cookies."""
        _validate_csrf(csrf_cookie=csrf_cookie, csrf_header=csrf_header)
        if refresh_token is not None:
            await RefreshSessionService(session).revoke_session(refresh_token)
            await session.commit()

        _clear_auth_cookies(response, settings)
        response.status_code = status.HTTP_204_NO_CONTENT
        return response

    current_user_dependency = Depends(current_user)

    @router.get("/me", response_model=UserResponse)
    async def me(user: UserResponse = current_user_dependency) -> UserResponse:
        """Return the current authenticated user."""
        return user

    return router


async def _issue_browser_session(
    *,
    response: Response,
    session: AsyncSession,
    settings: Settings,
    token_signer: TokenSigner,
    user: User,
    role: Role,
) -> AuthResponse:
    access_token = token_signer.create_access_token(user_id=user.id, role_name=role.name)
    access_expires_at = datetime.now(UTC) + timedelta(seconds=settings.access_token_ttl_seconds)
    refresh_expires_at = datetime.now(UTC) + timedelta(seconds=settings.refresh_token_ttl_seconds)
    issued_refresh = await RefreshSessionService(session).issue_session(
        user_id=user.id,
        expires_at=refresh_expires_at,
    )
    await session.commit()

    _set_cookie(
        response,
        settings=settings,
        name=settings.access_cookie_name,
        value=access_token,
        max_age=settings.access_token_ttl_seconds,
    )
    _set_cookie(
        response,
        settings=settings,
        name=settings.refresh_cookie_name,
        value=issued_refresh.refresh_token,
        max_age=settings.refresh_token_ttl_seconds,
    )
    _set_cookie(
        response,
        settings=settings,
        name=settings.csrf_cookie_name,
        value=secrets.token_urlsafe(32),
        max_age=settings.refresh_token_ttl_seconds,
        httponly=False,
    )
    return AuthResponse(user=_serialize_user(user, role), access_expires_at=access_expires_at)


async def _fetch_user_with_role(
    session: AsyncSession,
    *,
    email: str | None = None,
    user_id: UUID | None = None,
) -> tuple[User, Role] | None:
    statement = select(User, Role).join(Role, User.role_id == Role.id)
    if email is not None:
        statement = statement.where(User.email == email.lower())
    if user_id is not None:
        statement = statement.where(User.id == user_id)

    row = (await session.execute(statement)).first()
    if row is None:
        return None
    return row[0], row[1]


def _serialize_user(user: User, role: Role) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=role.name,
    )


def _set_cookie(
    response: Response,
    *,
    settings: Settings,
    name: str,
    value: str,
    max_age: int,
    httponly: bool = True,
) -> None:
    response.set_cookie(
        key=name,
        value=value,
        max_age=max_age,
        httponly=httponly,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
    )


def _clear_auth_cookies(response: Response, settings: Settings) -> None:
    for cookie_name in [
        settings.access_cookie_name,
        settings.refresh_cookie_name,
        settings.csrf_cookie_name,
    ]:
        response.delete_cookie(
            key=cookie_name,
            secure=settings.cookie_secure,
            samesite=settings.cookie_samesite,
        )


def _invalid_credentials() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password",
    )


def _auth_required() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
    )


def _refresh_required() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Refresh session expired or revoked",
    )


def _validate_csrf(*, csrf_cookie: str | None, csrf_header: str | None) -> None:
    if csrf_cookie is None or csrf_header is None:
        raise _csrf_failed()
    if not hmac.compare_digest(csrf_cookie, csrf_header):
        raise _csrf_failed()


def _csrf_failed() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="CSRF validation failed",
    )
