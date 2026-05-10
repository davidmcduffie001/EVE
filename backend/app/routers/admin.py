"""Administrative API routes."""

from __future__ import annotations

import hmac
from datetime import datetime
from uuid import UUID

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.database import get_db_session
from app.models.base import AuditLog, Role, User, utc_now
from app.services.audit import AuditLogService
from app.services.auth.dependencies import (
    AuthenticatedUser,
    client_host,
    create_current_user_dependency,
    create_permission_dependency,
)
from app.services.auth.permissions import PERMISSIONS
from app.services.auth.security import PasswordHasher

BUILT_IN_ADMIN_EMAIL = "admin@example.test"


class AuditLogEntryResponse(BaseModel):
    """Audit log entry returned to administrators."""

    id: UUID
    occurred_at: datetime
    user_id: UUID | None
    action: str
    resource_type: str
    resource_id: str | None
    outcome: str
    source_ip: str | None
    metadata: dict
    previous_hash: str
    entry_hash: str


class AuditLogListResponse(BaseModel):
    """Paginated audit log response envelope."""

    items: list[AuditLogEntryResponse]
    page: int
    page_size: int
    total: int


class RoleResponse(BaseModel):
    """Role returned to administrators."""

    id: UUID
    name: str
    is_system_role: bool
    permissions: list[str]


class RoleListResponse(BaseModel):
    """Paginated role list response."""

    items: list[RoleResponse]
    page: int
    page_size: int
    total: int


class RoleCreateRequest(BaseModel):
    """Custom role creation request."""

    name: str = Field(min_length=1, max_length=120)
    permissions: list[str] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        """Trim role names before persistence."""
        normalized = value.strip()
        if not normalized:
            raise ValueError("Role name is required")
        return normalized


class UserRoleResponse(BaseModel):
    """Small role object embedded in user responses."""

    id: UUID
    name: str


class UserResponse(BaseModel):
    """User returned to administrators."""

    id: UUID
    email: str
    display_name: str
    role: UserRoleResponse
    disabled: bool
    mfa_enrolled: bool
    created_at: datetime


class UserListResponse(BaseModel):
    """Paginated user list response."""

    items: list[UserResponse]
    page: int
    page_size: int
    total: int


class UserCreateRequest(BaseModel):
    """Local user creation request."""

    email: str
    display_name: str = Field(min_length=1, max_length=200)
    role_id: UUID
    password: str = Field(min_length=12, max_length=256)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        """Normalize email addresses used as local login keys."""
        normalized = value.strip().lower()
        if "@" not in normalized:
            raise ValueError("A valid email address is required")
        return normalized

    @field_validator("display_name")
    @classmethod
    def normalize_display_name(cls, value: str) -> str:
        """Trim display names before persistence."""
        normalized = value.strip()
        if not normalized:
            raise ValueError("Display name is required")
        return normalized


class UserUpdateRequest(BaseModel):
    """Administrative user update request."""

    email: str | None = None
    display_name: str | None = Field(default=None, max_length=200)
    role_id: UUID | None = None
    disabled: bool | None = None

    @field_validator("email")
    @classmethod
    def normalize_optional_email(cls, value: str | None) -> str | None:
        """Normalize optional email updates."""
        if value is None:
            return None
        normalized = value.strip().lower()
        if "@" not in normalized:
            raise ValueError("A valid email address is required")
        return normalized


class SsoSettingsResponse(BaseModel):
    """Stubbed SSO configuration returned to administrators."""

    enabled: bool = False
    provider: str = "oidc"
    display_name: str = ""
    issuer_url: str = ""
    client_id: str = ""
    metadata_url: str = ""
    auto_provision: bool = False
    default_role: str = "Analyst"
    client_secret_configured: bool = False


class SsoSettingsUpdateRequest(BaseModel):
    """Stubbed SSO configuration update request."""

    enabled: bool = False
    provider: str = Field(default="oidc", pattern="^(oidc|saml)$")
    display_name: str = Field(default="", max_length=200)
    issuer_url: str = Field(default="", max_length=2048)
    client_id: str = Field(default="", max_length=255)
    metadata_url: str = Field(default="", max_length=2048)
    client_secret: str | None = Field(default=None, max_length=2048)
    auto_provision: bool = False
    default_role: str = Field(default="Analyst", max_length=120)


_sso_settings = SsoSettingsResponse()


def create_admin_router(
    settings: Settings,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> APIRouter:
    """Create administrative routes with concrete runtime dependencies."""
    router = APIRouter(prefix="/admin", tags=["Administration"])
    db_dependency = get_db_session(sessionmaker)
    can_read_audit = create_permission_dependency(settings, sessionmaker, "audit:read")
    can_manage_users = create_permission_dependency(settings, sessionmaker, "users:manage")
    can_manage_roles = create_permission_dependency(settings, sessionmaker, "roles:manage")
    current_user = create_current_user_dependency(settings, sessionmaker)
    audit_reader = Depends(can_read_audit)
    user_manager = Depends(can_manage_users)
    role_manager = Depends(can_manage_roles)
    administration_reader = Depends(current_user)
    db_session = Depends(db_dependency)
    password_hasher = PasswordHasher()

    @router.get("/audit-log", response_model=AuditLogListResponse)
    async def list_audit_log(
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=200),
        _user: AuthenticatedUser = audit_reader,
        session: AsyncSession = db_session,
    ) -> AuditLogListResponse:
        """List tamper-evident audit log entries. Requires `audit:read`."""
        total = await session.scalar(select(func.count()).select_from(AuditLog))
        statement = (
            select(AuditLog)
            .order_by(AuditLog.occurred_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        rows = (await session.scalars(statement)).all()
        return AuditLogListResponse(
            items=[_serialize_audit_log(row) for row in rows],
            page=page,
            page_size=page_size,
            total=total or 0,
        )

    @router.get("/sso", response_model=SsoSettingsResponse)
    async def get_sso_settings(
        _user: AuthenticatedUser = role_manager,
    ) -> SsoSettingsResponse:
        """Return stubbed SSO configuration. Requires `roles:manage`."""
        return _sso_settings

    @router.put("/sso", response_model=SsoSettingsResponse)
    async def update_sso_settings(
        payload: SsoSettingsUpdateRequest,
        http_request: Request,
        csrf_cookie: str | None = Cookie(default=None, alias=settings.csrf_cookie_name),
        csrf_header: str | None = Header(default=None, alias=settings.csrf_header_name),
        actor: AuthenticatedUser = role_manager,
        session: AsyncSession = db_session,
    ) -> SsoSettingsResponse:
        """Update stubbed SSO configuration. Requires `roles:manage`."""
        _validate_csrf(csrf_cookie=csrf_cookie, csrf_header=csrf_header)
        global _sso_settings
        _sso_settings = SsoSettingsResponse(
            enabled=payload.enabled,
            provider=payload.provider,
            display_name=payload.display_name.strip(),
            issuer_url=payload.issuer_url.strip(),
            client_id=payload.client_id.strip(),
            metadata_url=payload.metadata_url.strip(),
            auto_provision=payload.auto_provision,
            default_role=payload.default_role.strip(),
            client_secret_configured=bool(payload.client_secret)
            or _sso_settings.client_secret_configured,
        )
        await _record_admin_event(
            session=session,
            http_request=http_request,
            actor=actor,
            action="admin.sso_update",
            resource_type="sso",
            resource_id="default",
            metadata={"enabled": _sso_settings.enabled, "provider": _sso_settings.provider},
        )
        await session.commit()
        return _sso_settings

    @router.get("/users", response_model=UserListResponse)
    async def list_users(
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=200),
        _user: AuthenticatedUser = user_manager,
        session: AsyncSession = db_session,
    ) -> UserListResponse:
        """List local users. Requires `users:manage`."""
        total = await session.scalar(select(func.count()).select_from(User))
        statement = (
            select(User, Role)
            .join(Role, User.role_id == Role.id)
            .order_by(User.email)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        rows = (await session.execute(statement)).all()
        return UserListResponse(
            items=[_serialize_user(user, role) for user, role in rows],
            page=page,
            page_size=page_size,
            total=total or 0,
        )

    @router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
    async def create_user(
        payload: UserCreateRequest,
        http_request: Request,
        csrf_cookie: str | None = Cookie(default=None, alias=settings.csrf_cookie_name),
        csrf_header: str | None = Header(default=None, alias=settings.csrf_header_name),
        actor: AuthenticatedUser = user_manager,
        session: AsyncSession = db_session,
    ) -> UserResponse:
        """Create a local user. Requires `users:manage`."""
        _validate_csrf(csrf_cookie=csrf_cookie, csrf_header=csrf_header)
        role = await session.get(Role, payload.role_id)
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role does not exist",
            )
        existing = await session.scalar(select(User).where(User.email == payload.email))
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email is already in use",
            )
        user = User(
            email=payload.email,
            display_name=payload.display_name,
            role_id=role.id,
            password_hash=password_hasher.hash_password(payload.password),
        )
        session.add(user)
        await session.flush()
        await _record_admin_event(
            session=session,
            http_request=http_request,
            actor=actor,
            action="admin.user_create",
            resource_id=str(user.id),
            metadata={"email": user.email, "role": role.name},
        )
        await session.commit()
        return _serialize_user(user, role)

    @router.patch("/users/{user_id}", response_model=UserResponse)
    async def update_user(
        user_id: UUID,
        payload: UserUpdateRequest,
        http_request: Request,
        csrf_cookie: str | None = Cookie(default=None, alias=settings.csrf_cookie_name),
        csrf_header: str | None = Header(default=None, alias=settings.csrf_header_name),
        actor: AuthenticatedUser = user_manager,
        session: AsyncSession = db_session,
    ) -> UserResponse:
        """Update a local user. Requires `users:manage`."""
        _validate_csrf(csrf_cookie=csrf_cookie, csrf_header=csrf_header)
        user = await session.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        if payload.email is not None and payload.email != user.email:
            existing = await session.scalar(select(User).where(User.email == payload.email))
            if existing is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email is already in use",
                )
            user.email = payload.email
        if payload.display_name is not None:
            user.display_name = payload.display_name.strip()
        if payload.role_id is not None:
            if user.email == BUILT_IN_ADMIN_EMAIL and payload.role_id != user.role_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Built-in Admin user role cannot be changed",
                )
            role = await session.get(Role, payload.role_id)
            if role is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Role does not exist",
                )
            user.role_id = role.id
        if payload.disabled is not None:
            if payload.disabled and user.email == BUILT_IN_ADMIN_EMAIL:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Built-in Admin user cannot be disabled",
                )
            user.disabled_at = utc_now() if payload.disabled else None

        role = await session.get(Role, user.role_id)
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role does not exist",
            )
        await _record_admin_event(
            session=session,
            http_request=http_request,
            actor=actor,
            action="admin.user_update",
            resource_id=str(user.id),
            metadata={"email": user.email, "disabled": user.disabled_at is not None},
        )
        await session.commit()
        return _serialize_user(user, role)

    @router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_user(
        user_id: UUID,
        http_request: Request,
        response: Response,
        csrf_cookie: str | None = Cookie(default=None, alias=settings.csrf_cookie_name),
        csrf_header: str | None = Header(default=None, alias=settings.csrf_header_name),
        actor: AuthenticatedUser = user_manager,
        session: AsyncSession = db_session,
    ) -> Response:
        """Delete a local user. Requires `users:manage`."""
        _validate_csrf(csrf_cookie=csrf_cookie, csrf_header=csrf_header)
        user = await session.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        if user.email == BUILT_IN_ADMIN_EMAIL:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Built-in Admin user cannot be deleted",
            )
        if actor.id == user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Users cannot delete their own account",
            )
        await _record_admin_event(
            session=session,
            http_request=http_request,
            actor=actor,
            action="admin.user_delete",
            resource_id=str(user.id),
            metadata={"email": user.email},
        )
        await session.delete(user)
        await session.commit()
        response.status_code = status.HTTP_204_NO_CONTENT
        return response

    @router.delete("/users/{user_id}/mfa", response_model=UserResponse)
    async def clear_user_mfa(
        user_id: UUID,
        http_request: Request,
        csrf_cookie: str | None = Cookie(default=None, alias=settings.csrf_cookie_name),
        csrf_header: str | None = Header(default=None, alias=settings.csrf_header_name),
        actor: AuthenticatedUser = user_manager,
        session: AsyncSession = db_session,
    ) -> UserResponse:
        """Clear MFA configuration for a local user. Requires `users:manage`."""
        _validate_csrf(csrf_cookie=csrf_cookie, csrf_header=csrf_header)
        user = await session.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        if actor.id == user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Users cannot clear their own MFA configuration",
            )
        user.mfa_enrolled = False
        user.mfa_secret = None
        role = await session.get(Role, user.role_id)
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role does not exist",
            )
        await _record_admin_event(
            session=session,
            http_request=http_request,
            actor=actor,
            action="admin.user_mfa_clear",
            resource_id=str(user.id),
            metadata={"email": user.email},
        )
        await session.commit()
        return _serialize_user(user, role)

    @router.get("/roles", response_model=RoleListResponse)
    async def list_roles(
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=200),
        actor: AuthenticatedUser = administration_reader,
        session: AsyncSession = db_session,
    ) -> RoleListResponse:
        """List roles. Requires `roles:manage` or `users:manage`."""
        _require_any_permission(actor, ("roles:manage", "users:manage"))
        total = await session.scalar(select(func.count()).select_from(Role))
        rows = (
            await session.scalars(
                select(Role).order_by(Role.name).offset((page - 1) * page_size).limit(page_size)
            )
        ).all()
        return RoleListResponse(
            items=[_serialize_role(role) for role in rows],
            page=page,
            page_size=page_size,
            total=total or 0,
        )

    @router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
    async def create_role(
        payload: RoleCreateRequest,
        http_request: Request,
        csrf_cookie: str | None = Cookie(default=None, alias=settings.csrf_cookie_name),
        csrf_header: str | None = Header(default=None, alias=settings.csrf_header_name),
        actor: AuthenticatedUser = role_manager,
        session: AsyncSession = db_session,
    ) -> RoleResponse:
        """Create a custom role. Requires `roles:manage`."""
        _validate_csrf(csrf_cookie=csrf_cookie, csrf_header=csrf_header)
        _validate_permissions(payload.permissions)
        existing = await session.scalar(select(Role).where(Role.name == payload.name))
        if existing is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Role already exists")
        role = Role(name=payload.name, is_system_role=False, permissions=payload.permissions)
        session.add(role)
        await session.flush()
        await _record_admin_event(
            session=session,
            http_request=http_request,
            actor=actor,
            action="admin.role_create",
            resource_type="role",
            resource_id=str(role.id),
            metadata={"name": role.name, "permissions": role.permissions},
        )
        await session.commit()
        return _serialize_role(role)

    @router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_role(
        role_id: UUID,
        http_request: Request,
        response: Response,
        csrf_cookie: str | None = Cookie(default=None, alias=settings.csrf_cookie_name),
        csrf_header: str | None = Header(default=None, alias=settings.csrf_header_name),
        actor: AuthenticatedUser = role_manager,
        session: AsyncSession = db_session,
    ) -> Response:
        """Delete a custom role. Requires `roles:manage`."""
        _validate_csrf(csrf_cookie=csrf_cookie, csrf_header=csrf_header)
        role = await session.get(Role, role_id)
        if role is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
        if role.is_system_role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="System roles cannot be deleted",
            )
        assigned_users = await session.scalar(
            select(func.count()).select_from(User).where(User.role_id == role.id)
        )
        if assigned_users:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role is assigned to users",
            )
        await _record_admin_event(
            session=session,
            http_request=http_request,
            actor=actor,
            action="admin.role_delete",
            resource_type="role",
            resource_id=str(role.id),
            metadata={"name": role.name},
        )
        await session.delete(role)
        await session.commit()
        response.status_code = status.HTTP_204_NO_CONTENT
        return response

    return router


def _serialize_audit_log(row: AuditLog) -> AuditLogEntryResponse:
    return AuditLogEntryResponse(
        id=row.id,
        occurred_at=row.occurred_at,
        user_id=row.user_id,
        action=row.action,
        resource_type=row.resource_type,
        resource_id=row.resource_id,
        outcome=row.outcome,
        source_ip=row.source_ip,
        metadata=row.metadata_json,
        previous_hash=row.previous_hash,
        entry_hash=row.entry_hash,
    )


def _serialize_role(role: Role) -> RoleResponse:
    return RoleResponse(
        id=role.id,
        name=role.name,
        is_system_role=role.is_system_role,
        permissions=role.permissions,
    )


def _serialize_user(user: User, role: Role) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=UserRoleResponse(id=role.id, name=role.name),
        disabled=user.disabled_at is not None,
        mfa_enrolled=user.mfa_enrolled,
        created_at=user.created_at,
    )


def _validate_permissions(permissions: list[str]) -> None:
    invalid_permissions = sorted(set(permissions) - PERMISSIONS)
    if invalid_permissions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown permissions: {', '.join(invalid_permissions)}",
        )


def _require_any_permission(user: AuthenticatedUser, permissions: tuple[str, ...]) -> None:
    if "*" in user.permissions or any(permission in user.permissions for permission in permissions):
        return
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")


async def _record_admin_event(
    *,
    session: AsyncSession,
    http_request: Request,
    actor: AuthenticatedUser,
    action: str,
    resource_id: str,
    resource_type: str = "user",
    metadata: dict | None = None,
) -> None:
    await AuditLogService(session).record(
        user_id=actor.id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome="success",
        source_ip=client_host(http_request),
        metadata=metadata or {},
    )


def _validate_csrf(*, csrf_cookie: str | None, csrf_header: str | None) -> None:
    if csrf_cookie is None or csrf_header is None:
        raise_csrf_failed()
    if not hmac.compare_digest(csrf_cookie, csrf_header):
        raise_csrf_failed()


def raise_csrf_failed() -> None:
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="CSRF validation failed",
    )
