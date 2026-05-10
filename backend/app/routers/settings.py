"""Authenticated user settings API routes."""

from __future__ import annotations

import hmac
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.database import get_db_session
from app.models.base import User, UserPreference
from app.services.audit import AuditLogService
from app.services.auth.dependencies import (
    AuthenticatedUser,
    client_host,
    create_current_user_dependency,
    fetch_user_with_role,
)
from app.services.auth.security import PasswordHasher
from app.services.auth.sessions import RefreshSessionService


class ProfileResponse(BaseModel):
    """Current user's account profile."""

    id: str
    email: str
    display_name: str
    role: str
    mfa_enrolled: bool
    created_at: datetime


class ProfileUpdateRequest(BaseModel):
    """Mutable profile fields."""

    email: str | None = None
    display_name: str | None = Field(default=None, max_length=200)
    current_password: str | None = None

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str | None) -> str | None:
        """Normalize profile email updates."""
        if value is None:
            return None
        normalized = value.strip().lower()
        if "@" not in normalized:
            raise ValueError("A valid email address is required")
        return normalized

    @field_validator("display_name")
    @classmethod
    def normalize_display_name(cls, value: str | None) -> str | None:
        """Normalize profile display-name updates."""
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("Display name is required")
        return normalized


class PasswordUpdateRequest(BaseModel):
    """Password change request."""

    current_password: str
    new_password: str = Field(min_length=12, max_length=256)


class PreferencesResponse(BaseModel):
    """Current user's display and table preferences."""

    theme_preference: Literal["dark", "light"]
    timezone: str
    date_format: str
    default_landing_page: str
    table_state: dict


class PreferencesUpdateRequest(BaseModel):
    """Mutable user preference fields."""

    theme_preference: Literal["dark", "light"] | None = None
    timezone: str | None = Field(default=None, max_length=100)
    date_format: str | None = Field(default=None, max_length=40)
    default_landing_page: str | None = Field(default=None, max_length=120)
    table_state: dict | None = None


def create_settings_router(
    settings: Settings,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> APIRouter:
    """Create authenticated user settings routes."""
    router = APIRouter(prefix="/settings", tags=["Settings"])
    db_dependency = get_db_session(sessionmaker)
    db_session = Depends(db_dependency)
    current_user = create_current_user_dependency(settings, sessionmaker)
    current_user_dependency = Depends(current_user)
    password_hasher = PasswordHasher()

    @router.get("/profile", response_model=ProfileResponse)
    async def get_profile(
        auth_user: AuthenticatedUser = current_user_dependency,
        session: AsyncSession = db_session,
    ) -> ProfileResponse:
        """Return the current user's account profile."""
        user_with_role = await fetch_user_with_role(session, user_id=auth_user.id)
        if user_with_role is None:
            raise_auth_required()
        user, role = user_with_role
        return _serialize_profile(user, role.name)

    @router.patch("/profile", response_model=ProfileResponse)
    async def update_profile(
        payload: ProfileUpdateRequest,
        http_request: Request,
        csrf_cookie: str | None = Cookie(default=None, alias=settings.csrf_cookie_name),
        csrf_header: str | None = Header(default=None, alias=settings.csrf_header_name),
        auth_user: AuthenticatedUser = current_user_dependency,
        session: AsyncSession = db_session,
    ) -> ProfileResponse:
        """Update the current user's display name or email."""
        _validate_csrf(csrf_cookie=csrf_cookie, csrf_header=csrf_header)
        user_with_role = await fetch_user_with_role(session, user_id=auth_user.id)
        if user_with_role is None:
            raise_auth_required()
        user, role = user_with_role

        email_changed = payload.email is not None and payload.email != user.email
        if email_changed:
            if payload.current_password is None:
                await _record_settings_event(
                    session=session,
                    http_request=http_request,
                    user=auth_user,
                    action="settings.profile_update",
                    outcome="failure",
                    metadata={"reason": "current_password_required", "field": "email"},
                )
                await session.commit()
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Current password is required to change email",
                )
            if not password_hasher.verify_password(payload.current_password, user.password_hash):
                await _record_settings_event(
                    session=session,
                    http_request=http_request,
                    user=auth_user,
                    action="settings.profile_update",
                    outcome="failure",
                    metadata={"reason": "invalid_current_password", "field": "email"},
                )
                await session.commit()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Current password is incorrect",
                )
            existing = await session.scalar(select(User).where(User.email == payload.email))
            if existing is not None and existing.id != user.id:
                await _record_settings_event(
                    session=session,
                    http_request=http_request,
                    user=auth_user,
                    action="settings.profile_update",
                    outcome="failure",
                    metadata={"reason": "duplicate_email"},
                )
                await session.commit()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email is already in use",
                )
            user.email = payload.email

        if payload.display_name is not None:
            user.display_name = payload.display_name

        await _record_settings_event(
            session=session,
            http_request=http_request,
            user=auth_user,
            action="settings.profile_update",
            outcome="success",
            metadata={
                "email_changed": email_changed,
                "display_name_changed": payload.display_name is not None,
            },
        )
        await session.commit()
        return _serialize_profile(user, role.name)

    @router.put("/password", status_code=status.HTTP_204_NO_CONTENT)
    async def update_password(
        payload: PasswordUpdateRequest,
        http_request: Request,
        response: Response,
        refresh_token: str | None = Cookie(default=None, alias=settings.refresh_cookie_name),
        csrf_cookie: str | None = Cookie(default=None, alias=settings.csrf_cookie_name),
        csrf_header: str | None = Header(default=None, alias=settings.csrf_header_name),
        auth_user: AuthenticatedUser = current_user_dependency,
        session: AsyncSession = db_session,
    ) -> Response:
        """Update the current user's password and revoke other sessions."""
        _validate_csrf(csrf_cookie=csrf_cookie, csrf_header=csrf_header)
        user = await session.get(User, auth_user.id)
        if user is None:
            raise_auth_required()
        if not password_hasher.verify_password(payload.current_password, user.password_hash):
            await _record_settings_event(
                session=session,
                http_request=http_request,
                user=auth_user,
                action="settings.password_update",
                outcome="failure",
                metadata={"reason": "invalid_current_password"},
            )
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Current password is incorrect",
            )

        user.password_hash = password_hasher.hash_password(payload.new_password)
        revoked_count = await RefreshSessionService(session).revoke_sessions_for_user(
            user_id=user.id,
            except_refresh_token=refresh_token,
        )
        await _record_settings_event(
            session=session,
            http_request=http_request,
            user=auth_user,
            action="settings.password_update",
            outcome="success",
            metadata={"revoked_refresh_sessions": revoked_count},
        )
        await session.commit()
        response.status_code = status.HTTP_204_NO_CONTENT
        return response

    @router.get("/preferences", response_model=PreferencesResponse)
    async def get_preferences(
        auth_user: AuthenticatedUser = current_user_dependency,
        session: AsyncSession = db_session,
    ) -> PreferencesResponse:
        """Return the current user's preferences."""
        user = await session.get(User, auth_user.id)
        if user is None:
            raise_auth_required()
        preferences = await _get_or_create_preferences(session, user)
        await session.commit()
        return _serialize_preferences(user, preferences)

    @router.put("/preferences", response_model=PreferencesResponse)
    async def update_preferences(
        payload: PreferencesUpdateRequest,
        http_request: Request,
        csrf_cookie: str | None = Cookie(default=None, alias=settings.csrf_cookie_name),
        csrf_header: str | None = Header(default=None, alias=settings.csrf_header_name),
        auth_user: AuthenticatedUser = current_user_dependency,
        session: AsyncSession = db_session,
    ) -> PreferencesResponse:
        """Update the current user's preferences."""
        _validate_csrf(csrf_cookie=csrf_cookie, csrf_header=csrf_header)
        user = await session.get(User, auth_user.id)
        if user is None:
            raise_auth_required()
        preferences = await _get_or_create_preferences(session, user)
        if payload.theme_preference is not None:
            user.theme_preference = payload.theme_preference
        if payload.timezone is not None:
            preferences.timezone = payload.timezone
        if payload.date_format is not None:
            preferences.date_format = payload.date_format
        if payload.default_landing_page is not None:
            preferences.default_landing_page = payload.default_landing_page
        if payload.table_state is not None:
            preferences.table_state = payload.table_state
        preferences.updated_at = datetime.now(UTC)

        await _record_settings_event(
            session=session,
            http_request=http_request,
            user=auth_user,
            action="settings.preferences_update",
            outcome="success",
        )
        await session.commit()
        return _serialize_preferences(user, preferences)

    return router


async def _get_or_create_preferences(
    session: AsyncSession,
    user: User,
) -> UserPreference:
    preferences = await session.get(UserPreference, user.id)
    if preferences is None:
        preferences = UserPreference(user_id=user.id)
        session.add(preferences)
        await session.flush()
    return preferences


async def _record_settings_event(
    *,
    session: AsyncSession,
    http_request: Request,
    user: AuthenticatedUser,
    action: str,
    outcome: str,
    metadata: dict | None = None,
) -> None:
    await AuditLogService(session).record(
        user_id=user.id,
        action=action,
        resource_type="user",
        resource_id=str(user.id),
        outcome=outcome,
        source_ip=client_host(http_request),
        metadata=metadata or {},
    )


def _serialize_profile(user: User, role_name: str) -> ProfileResponse:
    return ProfileResponse(
        id=str(user.id),
        email=user.email,
        display_name=user.display_name,
        role=role_name,
        mfa_enrolled=user.mfa_enrolled,
        created_at=user.created_at,
    )


def _serialize_preferences(user: User, preferences: UserPreference) -> PreferencesResponse:
    return PreferencesResponse(
        theme_preference=user.theme_preference,
        timezone=preferences.timezone,
        date_format=preferences.date_format,
        default_landing_page=preferences.default_landing_page,
        table_state=preferences.table_state,
    )


def _validate_csrf(*, csrf_cookie: str | None, csrf_header: str | None) -> None:
    if csrf_cookie is None or csrf_header is None:
        raise_csrf_failed()
    if not hmac.compare_digest(csrf_cookie, csrf_header):
        raise_csrf_failed()


def raise_auth_required() -> None:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
    )


def raise_csrf_failed() -> None:
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="CSRF validation failed",
    )
