"""Tamper-evident audit logging service."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import AuditLog

SENSITIVE_KEY_PARTS = ("password", "secret", "token", "key", "credential")


class AuditLogService:
    """Append-only audit log writer with hash-chain tamper evidence."""

    GENESIS_HASH = "0" * 64

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record(
        self,
        *,
        action: str,
        resource_type: str,
        outcome: str,
        user_id: UUID | None = None,
        resource_id: str | None = None,
        source_ip: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditLog:
        """Append an audit entry and return the pending ORM object."""
        occurred_at = datetime.now(UTC)
        redacted_metadata = redact_audit_metadata(metadata or {})
        previous_hash = await self._latest_entry_hash()
        entry_hash = self.hash_entry(
            occurred_at=occurred_at,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            source_ip=source_ip,
            metadata=redacted_metadata,
            previous_hash=previous_hash,
        )
        entry = AuditLog(
            occurred_at=occurred_at,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            source_ip=source_ip,
            metadata_json=redacted_metadata,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )
        self.session.add(entry)
        await self.session.flush()
        return entry

    async def _latest_entry_hash(self) -> str:
        statement = select(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(1)
        latest = await self.session.scalar(statement)
        if latest is None:
            return self.GENESIS_HASH
        return latest.entry_hash

    @staticmethod
    def hash_entry(
        *,
        occurred_at: datetime,
        user_id: UUID | None,
        action: str,
        resource_type: str,
        resource_id: str | None,
        outcome: str,
        source_ip: str | None,
        metadata: dict[str, Any],
        previous_hash: str,
    ) -> str:
        """Hash canonical audit entry data."""
        payload = {
            "occurred_at": occurred_at.isoformat(),
            "user_id": str(user_id) if user_id is not None else None,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "outcome": outcome,
            "source_ip": source_ip,
            "metadata": metadata,
            "previous_hash": previous_hash,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def redact_audit_metadata(value: Any) -> Any:
    """Recursively redact credential-like values from audit metadata."""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = str(key).lower()
            if any(part in normalized_key for part in SENSITIVE_KEY_PARTS):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_audit_metadata(item)
        return redacted
    if isinstance(value, list):
        return [redact_audit_metadata(item) for item in value]
    return value
