"""Reusable authentication and RBAC dependencies."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from fastapi import Cookie, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.database import get_db_session
from app.models.base import Role, User
from app.services.audit import AuditLogService
from app.services.auth.security import InvalidTokenError, TokenSigner


@dataclass(frozen=True)
class AuthenticatedUser:
    """Authenticated user context for route dependencies."""

    id: UUID
    email: str
    display_name: str
    role_id: UUID
    role_name: str
    permissions: frozenset[str]


def create_current_user_dependency(
    settings: Settings,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> Callable[..., object]:
    """Create a FastAPI dependency that resolves the current browser user."""
    db_dependency = get_db_session(sessionmaker)
    db_session = Depends(db_dependency)
    token_signer = TokenSigner(settings)

    async def current_user(
        access_token: str | None = Cookie(default=None, alias=settings.access_cookie_name),
        session: AsyncSession = db_session,
    ) -> AuthenticatedUser:
        if access_token is None:
            raise_auth_required()

        try:
            claims = token_signer.verify_access_token(access_token)
            user_id = UUID(claims.subject)
        except (InvalidTokenError, ValueError):
            raise_auth_required()

        user_with_role = await fetch_user_with_role(session, user_id=user_id)
        if user_with_role is None:
            raise_auth_required()

        user, role = user_with_role
        return serialize_authenticated_user(user, role)

    return current_user


def create_permission_dependency(
    settings: Settings,
    sessionmaker: async_sessionmaker[AsyncSession],
    required_permission: str,
) -> Callable[..., object]:
    """Create a dependency that requires a specific RBAC permission."""
    current_user = create_current_user_dependency(settings, sessionmaker)
    db_dependency = get_db_session(sessionmaker)
    current_user_dependency = Depends(current_user)
    db_session = Depends(db_dependency)

    async def permission_dependency(
        request: Request,
        user: AuthenticatedUser = current_user_dependency,
        session: AsyncSession = db_session,
    ) -> AuthenticatedUser:
        if "*" in user.permissions or required_permission in user.permissions:
            return user

        await AuditLogService(session).record(
            user_id=user.id,
            action="auth.permission_denied",
            resource_type="permission",
            resource_id=required_permission,
            outcome="denied",
            source_ip=client_host(request),
            metadata={"role": user.role_name, "required_permission": required_permission},
        )
        await session.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")

    return permission_dependency


async def fetch_user_with_role(
    session: AsyncSession,
    *,
    email: str | None = None,
    user_id: UUID | None = None,
) -> tuple[User, Role] | None:
    """Fetch a user with their role by email or ID."""
    statement = select(User, Role).join(Role, User.role_id == Role.id)
    if email is not None:
        statement = statement.where(User.email == email.lower())
    if user_id is not None:
        statement = statement.where(User.id == user_id)

    row = (await session.execute(statement)).first()
    if row is None:
        return None
    return row[0], row[1]


def serialize_authenticated_user(user: User, role: Role) -> AuthenticatedUser:
    """Serialize ORM user and role rows into route-safe auth context."""
    return AuthenticatedUser(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role_id=role.id,
        role_name=role.name,
        permissions=frozenset(role.permissions),
    )


def client_host(request: Request) -> str | None:
    """Return the client host FastAPI observed for an incoming request."""
    if request.client is None:
        return None
    return request.client.host


def raise_auth_required() -> None:
    """Raise the standard unauthenticated response."""
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
    )
