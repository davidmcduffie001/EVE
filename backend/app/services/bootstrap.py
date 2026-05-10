"""Idempotent seed data for a new EVE installation."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import ExploitIntelSource, Role

BUILTIN_ROLE_PERMISSIONS: dict[str, list[str]] = {
    "Admin": [
        "findings:read",
        "findings:export",
        "targets:manage",
        "intel:manage",
        "users:manage",
        "roles:manage",
        "audit:read",
        "reports:export",
        "scanners:manage",
    ],
    "Analyst": [
        "findings:read",
        "findings:export",
        "reports:export",
    ],
    "Read-Only": [
        "findings:read",
        "audit:read",
    ],
}

BUILTIN_INTEL_SOURCES: dict[str, dict[str, str | bool]] = {
    "nvd": {
        "source_class": "vulnerability_enrichment",
        "edition_required": "ce",
        "built_in": True,
        "enabled": True,
    },
    "searchsploit": {
        "source_class": "exploit_intelligence_metadata",
        "edition_required": "ce",
        "built_in": True,
        "enabled": True,
    },
}


async def seed_builtin_roles(session: AsyncSession) -> None:
    """Insert or update built-in system roles."""
    for role_name, permissions in BUILTIN_ROLE_PERMISSIONS.items():
        role = await session.scalar(select(Role).where(Role.name == role_name))
        if role is None:
            session.add(Role(name=role_name, is_system_role=True, permissions=permissions))
        else:
            role.is_system_role = True
            role.permissions = permissions
    await session.commit()


async def seed_builtin_intel_sources(session: AsyncSession) -> None:
    """Insert or update built-in immutable intelligence sources."""
    for provider, values in BUILTIN_INTEL_SOURCES.items():
        source = await session.scalar(
            select(ExploitIntelSource).where(ExploitIntelSource.provider == provider)
        )
        if source is None:
            session.add(ExploitIntelSource(provider=provider, **values))
        else:
            source.source_class = str(values["source_class"])
            source.edition_required = str(values["edition_required"])
            source.built_in = bool(values["built_in"])
            source.enabled = bool(values["enabled"])
    await session.commit()

