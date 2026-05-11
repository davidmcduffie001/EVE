"""Normalized finding API routes."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.database import get_db_session
from app.models.base import Finding, Scan, Target
from app.services.auth.dependencies import AuthenticatedUser, create_permission_dependency


class FindingResponse(BaseModel):
    """Finding read model for browser views."""

    id: UUID
    title: str
    description: str
    severity: str
    status: str
    confidence: str
    target_locator: str
    target_type: str
    scanner_type: str
    scanner_finding_id: str | None
    port: int | None
    protocol: str | None
    service_name: str | None
    cve_ids: list[str]
    first_seen_at: datetime
    last_seen_at: datetime


class FindingListResponse(BaseModel):
    """Paginated finding list response."""

    items: list[FindingResponse]
    page: int
    page_size: int
    total: int


def create_findings_router(
    settings: Settings,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> APIRouter:
    """Create finding read routes."""
    router = APIRouter(prefix="/findings", tags=["Findings"])
    db_session = Depends(get_db_session(sessionmaker))
    findings_reader = Depends(
        create_permission_dependency(settings, sessionmaker, "findings:read")
    )

    @router.get("", response_model=FindingListResponse)
    async def list_findings(
        page: int = 1,
        page_size: int = 50,
        _auth_user: AuthenticatedUser = findings_reader,
        session: AsyncSession = db_session,
    ) -> FindingListResponse:
        """List normalized scanner findings."""
        if page < 1 or page_size < 1 or page_size > 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid pagination parameters",
            )
        total = await session.scalar(select(func.count()).select_from(Finding))
        rows = (
            await session.execute(
                select(Finding, Target, Scan)
                .join(Target, Finding.target_id == Target.id)
                .join(Scan, Finding.scan_id == Scan.id)
                .order_by(Finding.last_seen_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).all()
        return FindingListResponse(
            items=[_serialize_finding(finding, target, scan) for finding, target, scan in rows],
            page=page,
            page_size=page_size,
            total=total or 0,
        )

    return router


def _serialize_finding(finding: Finding, target: Target, scan: Scan) -> FindingResponse:
    cve_ids = finding.tool_specific_data.get("cve_ids", [])
    if not isinstance(cve_ids, list):
        cve_ids = []
    return FindingResponse(
        id=finding.id,
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        status=finding.status,
        confidence=finding.confidence,
        target_locator=target.locator,
        target_type=target.locator_type,
        scanner_type=scan.scanner_type,
        scanner_finding_id=finding.scanner_finding_id,
        port=finding.port,
        protocol=finding.protocol,
        service_name=finding.service_name,
        cve_ids=[str(cve_id) for cve_id in cve_ids],
        first_seen_at=finding.first_seen_at,
        last_seen_at=finding.last_seen_at,
    )
