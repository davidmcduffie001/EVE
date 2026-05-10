"""Idempotent seed data for a new EVE installation."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import ExploitIntelSource, Role, User
from app.services.auth.permissions import BUILTIN_ROLE_PERMISSIONS
from app.services.auth.security import PasswordHasher

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


async def create_or_update_local_admin(
    session: AsyncSession,
    *,
    email: str,
    password: str,
    display_name: str,
) -> User:
    """Create or update a local Admin user for first-run development access."""
    normalized_email = email.strip().lower()
    if not normalized_email:
        raise ValueError("Admin email is required")
    if not password:
        raise ValueError("Admin password is required")
    if not display_name.strip():
        raise ValueError("Admin display name is required")

    await seed_builtin_roles(session)
    admin_role = await session.scalar(select(Role).where(Role.name == "Admin"))
    if admin_role is None:
        raise RuntimeError("Admin role was not seeded")

    password_hash = PasswordHasher().hash_password(password)
    user = await session.scalar(select(User).where(User.email == normalized_email))
    if user is None:
        user = User(
            email=normalized_email,
            display_name=display_name.strip(),
            role_id=admin_role.id,
            password_hash=password_hash,
        )
        session.add(user)
        await session.flush()
        return user

    user.display_name = display_name.strip()
    user.role_id = admin_role.id
    user.password_hash = password_hash
    user.disabled_at = None
    await session.flush()
    return user
