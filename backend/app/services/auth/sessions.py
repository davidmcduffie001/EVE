"""Persistent refresh-session service."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import RefreshSession, utc_now

REFRESH_TOKEN_BYTES = 32


@dataclass(frozen=True)
class IssuedRefreshSession:
    """A newly issued refresh session and one-time plaintext token."""

    session: RefreshSession
    refresh_token: str


class RefreshSessionService:
    """Issue, resolve, and revoke hashed refresh sessions."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the service with a database session."""
        self.session = session

    async def issue_session(
        self,
        *,
        user_id: UUID,
        expires_at: datetime,
        user_agent: str | None = None,
        source_ip: str | None = None,
    ) -> IssuedRefreshSession:
        """Create a persistent refresh session and return its plaintext token once."""
        refresh_token = secrets.token_urlsafe(REFRESH_TOKEN_BYTES)
        refresh_session = RefreshSession(
            user_id=user_id,
            refresh_token_hash=self.hash_refresh_token(refresh_token),
            user_agent=user_agent,
            source_ip=source_ip,
            expires_at=expires_at,
        )
        self.session.add(refresh_session)
        await self.session.flush()
        return IssuedRefreshSession(session=refresh_session, refresh_token=refresh_token)

    async def get_active_session(self, refresh_token: str) -> RefreshSession | None:
        """Resolve an active session by plaintext refresh token."""
        refresh_token_hash = self.hash_refresh_token(refresh_token)
        statement = select(RefreshSession).where(
            RefreshSession.refresh_token_hash == refresh_token_hash,
            RefreshSession.revoked_at.is_(None),
            RefreshSession.expires_at > datetime.now(UTC),
        )
        return await self.session.scalar(statement)

    async def revoke_session(self, refresh_token: str) -> bool:
        """Revoke an active refresh session by plaintext token."""
        refresh_session = await self.get_active_session(refresh_token)
        if refresh_session is None:
            return False

        refresh_session.revoked_at = utc_now()
        await self.session.flush()
        return True

    @staticmethod
    def hash_refresh_token(refresh_token: str) -> str:
        """Create a stable lookup hash for a refresh token."""
        return hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
