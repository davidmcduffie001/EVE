"""Administrative API routes."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.database import get_db_session
from app.models.base import AuditLog
from app.services.auth.dependencies import AuthenticatedUser, create_permission_dependency


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


def create_admin_router(
    settings: Settings,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> APIRouter:
    """Create administrative routes with concrete runtime dependencies."""
    router = APIRouter(prefix="/admin", tags=["Administration"])
    db_dependency = get_db_session(sessionmaker)
    can_read_audit = create_permission_dependency(settings, sessionmaker, "audit:read")
    audit_reader = Depends(can_read_audit)
    db_session = Depends(db_dependency)

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
