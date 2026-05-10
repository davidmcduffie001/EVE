"""SQLAlchemy ORM model definitions for the Phase 1 EVE schema."""

from __future__ import annotations

from datetime import UTC, date, datetime
from uuid import UUID, uuid4

from sqlalchemy import JSON, Boolean, Date, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""


class Role(Base):
    """Role containing a permission registry assignment."""

    __tablename__ = "roles"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    is_system_role: Mapped[bool] = mapped_column(Boolean, default=False)
    permissions: Mapped[list[str]] = mapped_column(JSON, default=list)


class User(Base):
    """Local user account."""

    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(200))
    role_id: Mapped[UUID] = mapped_column(ForeignKey("roles.id"))
    password_hash: Mapped[str] = mapped_column(String(512))
    mfa_enrolled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(512), nullable=True)
    theme_preference: Mapped[str] = mapped_column(
        Enum("dark", "light", name="theme_preference"), default="dark"
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RefreshSession(Base):
    """Revocable refresh session for local authentication."""

    __tablename__ = "refresh_sessions"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), index=True)
    refresh_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UserPreference(Base):
    """Per-user display and table preferences."""

    __tablename__ = "user_preferences"

    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), primary_key=True)
    timezone: Mapped[str] = mapped_column(String(100), default="UTC")
    date_format: Mapped[str] = mapped_column(String(40), default="YYYY-MM-DD")
    default_landing_page: Mapped[str] = mapped_column(String(120), default="dashboard")
    table_state: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Target(Base):
    """Asset or locator assessed by a scanner."""

    __tablename__ = "targets"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    locator: Mapped[str] = mapped_column(String(2048), index=True)
    locator_type: Mapped[str] = mapped_column(
        Enum("host", "ip", "domain", "url", "cidr", name="target_locator_type")
    )
    tags: Mapped[dict] = mapped_column(JSON, default=dict)
    in_authorized_scope: Mapped[bool] = mapped_column(Boolean, default=False)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ScannerIntegration(Base):
    """Configured scanner integration and sync state."""

    __tablename__ = "scanner_integrations"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(200))
    scanner_type: Mapped[str] = mapped_column(
        Enum(
            "nessus",
            "tenable_sc",
            "greenbone",
            "burp_enterprise",
            "bloodhound",
            "qualys",
            "insightvm",
            name="scanner_type",
        )
    )
    edition_required: Mapped[str] = mapped_column(Enum("ce", "enterprise", name="edition_required"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    encrypted_credentials_ref: Mapped[str] = mapped_column(String(512))
    schedule: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    last_sync_status: Mapped[str] = mapped_column(
        Enum("never_run", "queued", "running", "succeeded", "failed", name="sync_status"),
        default="never_run",
    )
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Scan(Base):
    """Discrete scanner sync or scan import."""

    __tablename__ = "scans"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    scanner_integration_id: Mapped[UUID] = mapped_column(ForeignKey("scanner_integrations.id"))
    scanner_type: Mapped[str] = mapped_column(String(80))
    scanner_scan_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(
        Enum("queued", "running", "succeeded", "failed", "canceled", name="scan_status")
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_output_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)


class ScanTarget(Base):
    """Many-to-many association between scans and targets."""

    __tablename__ = "scan_targets"

    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scans.id"), primary_key=True)
    target_id: Mapped[UUID] = mapped_column(ForeignKey("targets.id"), primary_key=True)


class Finding(Base):
    """Normalized vulnerability finding."""

    __tablename__ = "findings"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scans.id"))
    target_id: Mapped[UUID] = mapped_column(ForeignKey("targets.id"))
    scanner_finding_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(
        Enum("critical", "high", "medium", "low", "info", name="finding_severity")
    )
    status: Mapped[str] = mapped_column(
        Enum(
            "open",
            "acknowledged",
            "false_positive",
            "remediated",
            "risk_accepted",
            name="finding_status",
        ),
        default="open",
    )
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(40), nullable=True)
    service_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    confidence: Mapped[str] = mapped_column(
        Enum("confirmed", "likely", "potential", "unknown", name="finding_confidence"),
        default="unknown",
    )
    assigned_to: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    tool_specific_data: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class CVE(Base):
    """Enriched CVE metadata."""

    __tablename__ = "cves"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    description: Mapped[str] = mapped_column(Text)
    affected_products: Mapped[dict] = mapped_column(JSON, default=dict)
    references: Mapped[dict] = mapped_column(JSON, default=dict)
    last_enriched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class FindingCVE(Base):
    """Many-to-many association between findings and CVEs."""

    __tablename__ = "finding_cves"

    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id"), primary_key=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.id"), primary_key=True)


class ExploitRecord(Base):
    """Metadata-only exploit intelligence record."""

    __tablename__ = "exploit_records"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.id"))
    source_url: Mapped[str] = mapped_column(String(2048))
    provider: Mapped[str] = mapped_column(
        Enum(
            "nvd",
            "searchsploit",
            "vulncheck",
            "rapid7",
            "vulners",
            "vuldb",
            "armis",
            "mitre",
            name="intel_provider",
        )
    )
    title: Mapped[str] = mapped_column(String(500))
    author: Mapped[str | None] = mapped_column(String(255), nullable=True)
    disclosure_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    exploit_type: Mapped[str | None] = mapped_column(String(120), nullable=True)
    reliability_rating: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ExploitIntelSource(Base):
    """Configured vulnerability enrichment or exploit metadata provider."""

    __tablename__ = "exploit_intel_sources"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    provider: Mapped[str] = mapped_column(String(80), unique=True)
    source_class: Mapped[str] = mapped_column(
        Enum(
            "vulnerability_enrichment",
            "exploit_intelligence_metadata",
            "combined",
            name="intel_source_class",
        )
    )
    edition_required: Mapped[str] = mapped_column(
        Enum("ce", "enterprise", name="intel_edition_required")
    )
    built_in: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    encrypted_api_key_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    last_health_status: Mapped[str] = mapped_column(
        Enum("unknown", "healthy", "degraded", "failed", name="health_status"),
        default="unknown",
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class License(Base):
    """Imported offline license state."""

    __tablename__ = "licenses"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    edition: Mapped[str] = mapped_column(Enum("ce", "enterprise", name="license_edition"))
    status: Mapped[str] = mapped_column(
        Enum("active", "expired", "invalid", "revoked", name="license_status")
    )
    issued_to: Mapped[str] = mapped_column(String(255))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    installation_id: Mapped[str] = mapped_column(String(255))
    feature_flags: Mapped[dict] = mapped_column(JSON, default=dict)
    signature: Mapped[str] = mapped_column(Text)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    imported_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"))


class ReportExport(Base):
    """Queued or completed report export."""

    __tablename__ = "report_exports"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    requested_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    format: Mapped[str] = mapped_column(Enum("csv", "json", "pdf", name="report_format"))
    status: Mapped[str] = mapped_column(
        Enum("queued", "running", "succeeded", "failed", "expired", name="export_status")
    )
    filters: Mapped[dict] = mapped_column(JSON, default=dict)
    storage_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Notification(Base):
    """In-app user notification."""

    __tablename__ = "notifications"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    type: Mapped[str] = mapped_column(String(120))
    title: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AuditLog(Base):
    """Tamper-evident audit log entry."""

    __tablename__ = "audit_logs"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(200))
    resource_type: Mapped[str] = mapped_column(String(120))
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    outcome: Mapped[str] = mapped_column(Enum("success", "failure", "denied", name="audit_outcome"))
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    previous_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))


class LegalAcknowledgment(Base):
    """Acknowledgment of legal documents by a user."""

    __tablename__ = "legal_acknowledgments"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    document_type: Mapped[str] = mapped_column(
        Enum(
            "eula",
            "acceptable_use_policy",
            "privacy_policy",
            "self_hosted_addendum",
            name="legal_document_type",
        )
    )
    document_version_hash: Mapped[str] = mapped_column(String(64))
    acknowledged_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
