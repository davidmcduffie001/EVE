"""Tests for tamper-evident audit logging."""

import pytest
from sqlalchemy import select

from app.core.database import create_sessionmaker
from app.models.base import AuditLog, Base
from app.services.audit import AuditLogService


@pytest.mark.asyncio
async def test_audit_log_entries_form_hash_chain() -> None:
    """Audit entries store the previous hash and hash canonical event data."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with sessionmaker() as session:
        service = AuditLogService(session)
        first = await service.record(
            action="auth.login",
            resource_type="session",
            outcome="success",
            source_ip="127.0.0.1",
            metadata={"email": "admin@example.test"},
        )
        second = await service.record(
            action="auth.logout",
            resource_type="session",
            outcome="success",
            source_ip="127.0.0.1",
            metadata={"reason": "user_requested"},
        )
        await session.commit()

    async with sessionmaker() as session:
        rows = (await session.scalars(select(AuditLog).order_by(AuditLog.occurred_at))).all()

    assert len(rows) == 2
    assert rows[0].previous_hash == AuditLogService.GENESIS_HASH
    assert rows[0].entry_hash == first.entry_hash
    assert rows[1].previous_hash == rows[0].entry_hash
    assert rows[1].entry_hash == second.entry_hash
    assert rows[0].entry_hash != rows[1].entry_hash

    await sessionmaker.kw["bind"].dispose()


@pytest.mark.asyncio
async def test_audit_log_redacts_sensitive_metadata_keys() -> None:
    """Credential-like metadata values are never persisted into audit payloads."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with sessionmaker() as session:
        service = AuditLogService(session)
        await service.record(
            action="auth.login",
            resource_type="session",
            outcome="failure",
            metadata={
                "email": "admin@example.test",
                "password": "correct-password",
                "nested": {"api_token": "secret-token"},
            },
        )
        await session.commit()

    async with sessionmaker() as session:
        row = await session.scalar(select(AuditLog))

    assert row is not None
    assert row.metadata_json["email"] == "admin@example.test"
    assert row.metadata_json["password"] == "[REDACTED]"  # noqa: S105
    assert row.metadata_json["nested"]["api_token"] == "[REDACTED]"  # noqa: S105

    await sessionmaker.kw["bind"].dispose()
