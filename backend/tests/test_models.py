"""Tests for the Phase 1 SQLAlchemy model surface."""

from app.models.base import Base


def test_phase_1_metadata_contains_expected_tables() -> None:
    """The baseline schema exposes Phase 1 tables only."""
    assert set(Base.metadata.tables) == {
        "audit_logs",
        "cves",
        "exploit_intel_sources",
        "exploit_records",
        "finding_cves",
        "findings",
        "legal_acknowledgments",
        "licenses",
        "notifications",
        "report_exports",
        "roles",
        "scan_targets",
        "scanner_integrations",
        "scans",
        "targets",
        "user_preferences",
        "refresh_sessions",
        "users",
    }


def test_phase_1_metadata_excludes_execution_tables() -> None:
    """Phase 2 execution and credential tables are not scaffolded in Phase 1."""
    assert "execution_jobs" not in Base.metadata.tables
    assert "execution_results" not in Base.metadata.tables
    assert "credentials" not in Base.metadata.tables


def test_findings_table_has_stable_identity_columns() -> None:
    """Findings keep scanner-native identity and dedupe fields."""
    findings = Base.metadata.tables["findings"]

    assert "scanner_finding_id" in findings.c
    assert "dedupe_key" in findings.c
    assert findings.c.dedupe_key.index is True
    assert "port" in findings.c
    assert "protocol" in findings.c
    assert "service_name" in findings.c
    assert "confidence" in findings.c
    assert "assigned_to" in findings.c


def test_users_table_has_authentication_columns() -> None:
    """Users keep a password hash but never a plaintext credential."""
    users = Base.metadata.tables["users"]

    assert "password_hash" in users.c
    assert "password" not in users.c


def test_refresh_sessions_table_tracks_revocable_session_state() -> None:
    """Refresh sessions support hashed token lookup and explicit revocation."""
    refresh_sessions = Base.metadata.tables["refresh_sessions"]

    assert "user_id" in refresh_sessions.c
    assert "refresh_token_hash" in refresh_sessions.c
    assert refresh_sessions.c.refresh_token_hash.unique is True
    assert "expires_at" in refresh_sessions.c
    assert "revoked_at" in refresh_sessions.c
