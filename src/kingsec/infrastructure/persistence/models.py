"""SQLAlchemy ORM models for KingSec persistence.

These classes are the DATABASE representation only. They are deliberately kept
separate from the pure domain entities (Data Mapper pattern): the domain never
imports SQLAlchemy, and these models never carry business rules. A dedicated
mapping layer (``mappers.py``) translates between the two worlds.

Storage decisions worth noting:
    * Timestamps are stored as ISO-8601 strings. SQLite has no native
      timezone-aware datetime type, and the domain requires tz-aware timestamps,
      so storing the ISO string round-trips the timezone losslessly.
    * Enums are stored by their ``name`` (e.g. "CRITICAL", "RUNNING") for
      readability when inspecting the database directly.
    * A ``Report`` is an immutable snapshot (a document), so its finding entries
      and severity counts are stored as JSON rather than normalised tables.
    * Child collections use ``cascade="all, delete-orphan"`` so removing an
      aggregate removes its children in one operation.
"""

from typing import Any

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON


class Base(DeclarativeBase):
    """Declarative base for all KingSec ORM models."""


class AssessmentORM(Base):
    """Row representation of an :class:`~kingsec.domain.Assessment` aggregate."""

    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    target_value: Mapped[str] = mapped_column(String, nullable=False)
    target_type: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)  # ISO-8601

    # Authorization is optional (an assessment may be DRAFT / unauthorized).
    authorized_by: Mapped[str | None] = mapped_column(String, nullable=True)
    authorized_at: Mapped[str | None] = mapped_column(String, nullable=True)
    authorization_scope: Mapped[str | None] = mapped_column(String, nullable=True)

    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    organization_id: Mapped[str | None] = mapped_column(String, ForeignKey("organizations.id"), nullable=True)
    team_id: Mapped[str | None] = mapped_column(String, ForeignKey("teams.id"), nullable=True)
    owner_id: Mapped[str | None] = mapped_column(String, nullable=True)

    # Which AssessmentProfile this scan was planned against. NULL means "no
    # profile" - the execution layer runs every target-compatible scanner,
    # exactly as it did before this feature existed.
    profile_id: Mapped[str | None] = mapped_column(String, nullable=True)
    # Final per-scanner outcome, written once at completion: list of
    # {"scanner_id", "name", "status", "findings_count", "skipped_reason"}.
    # Empty for assessments that predate this feature or never completed.
    scanner_summary: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)

    findings: Mapped[list["FindingORM"]] = relationship(
        back_populates="assessment",
        cascade="all, delete-orphan",
        lazy="selectin",  # avoid N+1: load all findings in one extra query
    )


class FindingORM(Base):
    """Row representation of a :class:`~kingsec.domain.Finding` entity."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    discovered_at: Mapped[str] = mapped_column(String, nullable=False)  # ISO-8601
    # CVE/CWE/CVSS: populated only for scanners that genuinely correlate to
    # this data (Nuclei, Trivy). Comma-separated strings rather than a JSON
    # column - consistent with this table's other plain-string columns, and
    # these are short lists of short IDs, not structured objects.
    cve_ids: Mapped[str | None] = mapped_column(String, nullable=True)
    cwe_ids: Mapped[str | None] = mapped_column(String, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String, nullable=True)

    assessment: Mapped[AssessmentORM] = relationship(back_populates="findings")
    evidence: Mapped[list["EvidenceORM"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", lazy="selectin"
    )
    recommendations: Mapped[list["RecommendationORM"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", lazy="selectin"
    )


class EvidenceORM(Base):
    """Row representation of an :class:`~kingsec.domain.Evidence` value object.

    Evidence has no domain identity, so it gets a surrogate autoincrement PK
    purely for the database.
    """

    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    summary: Mapped[str] = mapped_column(String, nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    collected_at: Mapped[str] = mapped_column(String, nullable=False)  # ISO-8601

    finding: Mapped[FindingORM] = relationship(back_populates="evidence")


class RecommendationORM(Base):
    """Row representation of a :class:`~kingsec.domain.Recommendation` value object."""

    __tablename__ = "recommendations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[str] = mapped_column(String, nullable=False)

    finding: Mapped[FindingORM] = relationship(back_populates="recommendations")


class ReportORM(Base):
    """Row representation of a :class:`~kingsec.domain.Report` snapshot.

    One report per assessment, so the assessment id is the primary key. The
    verdict is stored as queryable columns; the finding entries and severity
    counts are stored as JSON because a report is an immutable document.
    """

    __tablename__ = "reports"

    assessment_id: Mapped[str] = mapped_column(String, primary_key=True)
    target: Mapped[str] = mapped_column(String, nullable=False)
    generated_at: Mapped[str] = mapped_column(String, nullable=False)  # ISO-8601

    verdict_headline: Mapped[str] = mapped_column(String, nullable=False)
    verdict_action_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    verdict_highest_severity: Mapped[str | None] = mapped_column(String, nullable=True)

    # entries: list of dicts; severity_counts: list of [severity_name, count].
    entries: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    severity_counts: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    # Whether an AI provider was configured/available at generation time.
    ai_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Prior reports for the same target (risk-over-time chart): list of
    # {"generated_at": iso str, "executive_score": float}, oldest first.
    history: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    # Cover-page authorization metadata.
    authorized_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    scope: Mapped[str] = mapped_column(String, nullable=False, default="")
    # Snapshot of which scanners ran and why others were skipped, carried
    # over from the assessment at generation time - same shape as
    # AssessmentORM.scanner_summary.
    scanner_summary: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)


class UserORM(Base):
    """Row representation of a :class:`~kingsec.domain.User` entity.

    Passwords are stored as hashes only. Timestamps are ISO-8601 strings
    for SQLite compatibility.
    """

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, default="VIEWER")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)  # ISO-8601
    last_login_at: Mapped[str | None] = mapped_column(String, nullable=True)  # ISO-8601


class ApiKeyORM(Base):
    """Row representation of an :class:`~kingsec.domain.ApiKey` entity.

    Only the key hash is stored; the plaintext key is never persisted.
    """

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    key_hash: Mapped[str] = mapped_column(String, nullable=False)
    scope: Mapped[str] = mapped_column(String, nullable=False, default="read_only")
    status: Mapped[str] = mapped_column(String, nullable=False, default="active")
    last_used_at: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)


class AuditEntryORM(Base):
    """Immutable audit trail record.

    Append-only: no update or delete operations are provided on this model.
    Timestamps are indexed for efficient time-range queries. User ID and
    action are indexed for filtered queries.

    ``metadata_json`` stores extensible context as JSON text (SQLite has
    a native JSON type, but TEXT is more portable and sufficient for
    structured key-value data).
    """

    __tablename__ = "audit_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[str] = mapped_column(String, nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String, nullable=False, index=True, default="")
    username: Mapped[str] = mapped_column(String, nullable=False, default="")
    role: Mapped[str] = mapped_column(String, nullable=False, default="")
    action: Mapped[str] = mapped_column(String, nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String, nullable=False, default="")
    resource_id: Mapped[str] = mapped_column(String, nullable=False, default="")
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    ip_address: Mapped[str] = mapped_column(String, nullable=False, default="")
    user_agent: Mapped[str] = mapped_column(String, nullable=False, default="")
    correlation_id: Mapped[str] = mapped_column(String, nullable=False, default="")
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class AuditEventORM(Base):
    """Immutable enterprise audit event record.

    This is the Phase 8.4 enterprise audit table, separate from the legacy
    ``audit_entries`` table. Append-only: no update or delete operations.
    Timestamps are ISO-8601 strings. Enums are stored by value. Metadata is
    stored as a JSON string.
    """

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[str] = mapped_column(String, nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    actor_type: Mapped[str] = mapped_column(String, nullable=False)
    username: Mapped[str] = mapped_column(String, nullable=False)
    ip_address: Mapped[str] = mapped_column(String, nullable=False, default="")
    user_agent: Mapped[str] = mapped_column(String, nullable=False, default="")
    request_id: Mapped[str] = mapped_column(String, nullable=False, default="")
    action: Mapped[str] = mapped_column(String, nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String, nullable=False, default="")
    resource_id: Mapped[str] = mapped_column(String, nullable=False, default="")
    outcome: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False, default="")
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class MfaSecretORM(Base):
    """Per-user MFA TOTP secret.

    Only the Base32-encoded secret key is stored. Never expose outside the
    infrastructure layer unless returning it at enable-time (one-time view).
    """

    __tablename__ = "mfa_secrets"

    user_id: Mapped[str] = mapped_column(String, primary_key=True)
    secret_key: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="disabled")
    created_at: Mapped[str] = mapped_column(String, nullable=False)


class MfaRecoveryCodeORM(Base):
    """A single hashed recovery code for MFA fallback.

    Only the SHA-256 hash is stored. Plaintext codes are shown once at
    creation time and are never persisted.
    """

    __tablename__ = "mfa_recovery_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="active")


class SessionORM(Base):
    """Persistent user session record.

    Created on login, checked on every JWT validation, revoked on logout.
    Refresh-token rotation updates refresh_jti; old refresh reuse revokes.
    """

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    session_type: Mapped[str] = mapped_column(String, nullable=False, default="user")
    jti: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    refresh_jti: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    issued_at: Mapped[str] = mapped_column(String, nullable=False)
    expires_at: Mapped[str] = mapped_column(String, nullable=False, index=True)
    last_activity: Mapped[str] = mapped_column(String, nullable=False)
    client_ip: Mapped[str] = mapped_column(String, nullable=False, default="")
    user_agent: Mapped[str] = mapped_column(String, nullable=False, default="")
    device_name: Mapped[str] = mapped_column(String, nullable=False, default="")
    platform: Mapped[str] = mapped_column(String, nullable=False, default="")
    browser: Mapped[str] = mapped_column(String, nullable=False, default="")
    status: Mapped[str] = mapped_column(String, nullable=False, default="active", index=True)
    idle_timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=1800)


class RevokedTokenORM(Base):
    """A revoked JWT token tracked by its unique JTI.

    Tokens are persisted so revocation survives restarts. Expired entries are
    periodically cleaned up by a background task or on next verification.
    """

    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String, primary_key=True)
    revoked_at: Mapped[str] = mapped_column(String, nullable=False)  # ISO-8601
    expires_at: Mapped[str] = mapped_column(String, nullable=False, index=True)  # ISO-8601


class AccountLockoutORM(Base):
    """Row representation of an :class:`~kingsec.domain.rate_limit.AccountLockout`.

    One row per user with any recorded failed-login history. ``locked_until``
    is a Unix timestamp (matches ``ClockPort.now()``'s float epoch seconds) -
    0.0 means "tracking an attempt count that hasn't crossed the lockout
    threshold yet," not an active lock (see CheckAccountLockout).
    """

    __tablename__ = "account_lockouts"

    user_id: Mapped[str] = mapped_column(String, primary_key=True)
    locked_until: Mapped[float] = mapped_column(Float, nullable=False)
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False)


# ===========================================================================
#  Notification model
# ===========================================================================


class NotificationORM(Base):
    """Row representation of a notification."""

    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    channel: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    priority: Mapped[str] = mapped_column(String, nullable=False)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    template_vars: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_retries: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    read_at: Mapped[str | None] = mapped_column(String, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


# ===========================================================================
#  Scan-job / Asset models  (Phase 7.2)
# ===========================================================================


class ScanModel(Base):
    """A single scan execution against a target."""

    __tablename__ = "scan_results"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    target: Mapped[str] = mapped_column(String, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String, nullable=False, index=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)  # ISO-8601
    completed_at: Mapped[str | None] = mapped_column(String, nullable=True)  # ISO-8601
    scanner_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    findings: Mapped[list["FindingModel"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    reports: Mapped[list["ReportModel"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class FindingModel(Base):
    """A single finding discovered during a scan."""

    __tablename__ = "scan_findings"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False, index=True)
    scanner: Mapped[str | None] = mapped_column(String, nullable=True)
    asset: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)  # ISO-8601

    scan: Mapped[ScanModel] = relationship(back_populates="findings")

    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )


class ReportModel(Base):
    """A generated report document attached to a scan."""

    __tablename__ = "scan_reports"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False, index=True)
    format: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)  # ISO-8601
    content: Mapped[str] = mapped_column(Text, nullable=False)

    scan: Mapped[ScanModel] = relationship(back_populates="reports")


class JobModel(Base):
    """A scan job submitted for asynchronous execution."""

    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    status: Mapped[str] = mapped_column(String, nullable=False, index=True)
    target: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)  # ISO-8601
    updated_at: Mapped[str] = mapped_column(String, nullable=False)  # ISO-8601


class AssetModel(Base):
    """A discovered network or cloud asset."""

    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    asset_type: Mapped[str] = mapped_column(String, nullable=False, default="host")
    hostname: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    domain: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    fqdn: Mapped[str | None] = mapped_column(String, nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String, nullable=True)
    operating_system: Mapped[str | None] = mapped_column(String, nullable=True)
    os_version: Mapped[str | None] = mapped_column(String, nullable=True)
    owner: Mapped[str | None] = mapped_column(String, nullable=True)
    criticality: Mapped[str | None] = mapped_column(String, nullable=True)
    location: Mapped[str | None] = mapped_column(String, nullable=True)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    open_ports: Mapped[str | None] = mapped_column(String, nullable=True)
    certificate_issuer: Mapped[str | None] = mapped_column(String, nullable=True)
    certificate_expiry: Mapped[str | None] = mapped_column(String, nullable=True)
    tls_version: Mapped[str | None] = mapped_column(String, nullable=True)
    cloud_provider: Mapped[str | None] = mapped_column(String, nullable=True)
    cloud_region: Mapped[str | None] = mapped_column(String, nullable=True)
    container_runtime: Mapped[str | None] = mapped_column(String, nullable=True)
    container_image: Mapped[str | None] = mapped_column(String, nullable=True)
    database_type: Mapped[str | None] = mapped_column(String, nullable=True)
    database_version: Mapped[str | None] = mapped_column(String, nullable=True)
    web_server: Mapped[str | None] = mapped_column(String, nullable=True)
    programming_language: Mapped[str | None] = mapped_column(String, nullable=True)
    framework: Mapped[str | None] = mapped_column(String, nullable=True)
    cms: Mapped[str | None] = mapped_column(String, nullable=True)
    first_seen: Mapped[str | None] = mapped_column(String, nullable=True)
    last_seen: Mapped[str | None] = mapped_column(String, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    metadata_json: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str | None] = mapped_column(String, nullable=True, default=None)

    findings: Mapped[list[FindingModel]] = relationship(
        foreign_keys=[FindingModel.asset_id],
        lazy="selectin",
    )
    tags: Mapped[list["AssetTagModel"]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    technologies: Mapped[list["AssetTechnologyModel"]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class AssetTagModel(Base):
    __tablename__ = "asset_tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    key: Mapped[str] = mapped_column(String, nullable=False)
    value: Mapped[str] = mapped_column(String, nullable=False)

    asset: Mapped[AssetModel] = relationship(back_populates="tags")


class AssetTechnologyModel(Base):
    __tablename__ = "asset_technologies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    technology_type: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    version: Mapped[str | None] = mapped_column(String, nullable=True)
    vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    asset: Mapped[AssetModel] = relationship(back_populates="technologies")


class AssetRelationshipModel(Base):
    __tablename__ = "asset_relationships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    target_asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type: Mapped[str] = mapped_column(String, nullable=False)
    metadata_json: Mapped[str | None] = mapped_column(String, nullable=True)


class AssetHistoryModel(Base):
    __tablename__ = "asset_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False)
    timestamp: Mapped[str] = mapped_column(String, nullable=False)
    previous_value: Mapped[str | None] = mapped_column(String, nullable=True)
    new_value: Mapped[str | None] = mapped_column(String, nullable=True)
    actor: Mapped[str] = mapped_column(String, nullable=False, default="system")
    metadata_json: Mapped[str | None] = mapped_column(String, nullable=True)


class ScheduleORM(Base):
    """Row representation of a scheduled scan."""

    __tablename__ = "schedules"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, default="")
    owner_user_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    target: Mapped[str] = mapped_column(String, nullable=False)
    scanner_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    config: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    schedule_type: Mapped[str] = mapped_column(String, nullable=False)
    cron_expression: Mapped[str] = mapped_column(String, default="")
    timezone: Mapped[str] = mapped_column(String, default="UTC")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    paused: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    last_run: Mapped[str | None] = mapped_column(String, nullable=True)
    next_run: Mapped[str | None] = mapped_column(String, nullable=True)
    retry_strategy: Mapped[str] = mapped_column(String, default="no_retry")
    max_retries: Mapped[int] = mapped_column(Integer, default=0)
    retry_delay_seconds: Mapped[int] = mapped_column(Integer, default=0)
    current_retry_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String, default="active")
    # KSEC-85-02: optimistic-lock counter. Every successful UPDATE is
    # scoped to WHERE version = <the version the caller read> and sets
    # version = version + 1 (see SqlAlchemyScheduleRepository.save()) -
    # a mismatch means someone else wrote first, and the write is rejected
    # rather than silently overwriting or being silently overwritten.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class OrganizationORM(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    slug: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    # KSEC-86-01: optimistic-lock counter, same mechanism as
    # ScheduleORM.version (KSEC-85-02) - see
    # SQLAlchemyOrganizationRepository.save().
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class TeamORM(Base):
    __tablename__ = "teams"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    organization_id: Mapped[str] = mapped_column(String, ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    # KSEC-86-01: see OrganizationORM.version above.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class OrganizationMembershipORM(Base):
    __tablename__ = "organization_memberships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False)
    organization_id: Mapped[str] = mapped_column(String, ForeignKey("organizations.id"), nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, default="viewer")
    created_at: Mapped[str] = mapped_column(String, nullable=False)

    __table_args__ = (
        Index("ix_organization_memberships_user_org_unique", "user_id", "organization_id", unique=True),
    )


class TeamMembershipORM(Base):
    __tablename__ = "team_memberships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False)
    team_id: Mapped[str] = mapped_column(String, ForeignKey("teams.id"), nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)

    __table_args__ = (
        Index("ix_team_memberships_user_team_unique", "user_id", "team_id", unique=True),
    )


class LicenseORM(Base):
    __tablename__ = "licenses"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    edition: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    license_key: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    issued_to: Mapped[str] = mapped_column(String, nullable=False, default="")
    company: Mapped[str] = mapped_column(String, nullable=False, default="")
    email: Mapped[str] = mapped_column(String, nullable=False, default="")
    max_users: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_organizations: Mapped[int | None] = mapped_column(Integer, nullable=True)
    issued_at: Mapped[str] = mapped_column(String, nullable=False, default="")
    expires_at: Mapped[str] = mapped_column(String, nullable=False, default="")
    features: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    signature: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class AIProviderConfigORM(Base):
    """Admin-configured AI provider settings, persisted so they survive a
    restart and can be set from the UI instead of only via env vars.

    Single-row table (fixed ``id="singleton"``) — there is exactly one
    active AI provider configuration for the whole deployment, same
    "one settings row" shape as ``LicenseORM``. ``api_key_encrypted`` is
    Fernet ciphertext (via ``EncryptionServicePort``, keyed by
    ``SecretsSettings.encryption_key``) — the plaintext key is never
    persisted, only ever held in memory for the duration of a request.
    """

    __tablename__ = "ai_provider_config"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    provider: Mapped[str] = mapped_column(String, nullable=False)
    api_key_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    model: Mapped[str | None] = mapped_column(String, nullable=True)
    base_url: Mapped[str | None] = mapped_column(String, nullable=True)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class OrgActivityEventORM(Base):
    __tablename__ = "org_activity_events"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    organization_id: Mapped[str] = mapped_column(String, ForeignKey("organizations.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    actor_id: Mapped[str] = mapped_column(String, nullable=False)
    message: Mapped[str] = mapped_column(String, nullable=False)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[str] = mapped_column(String, nullable=False)


# ===========================================================================
#  Attack Surface Management models  (Phase 19)
# ===========================================================================


class ExposureModel(Base):
    __tablename__ = "exposures"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    asset_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    exposure_type: Mapped[str] = mapped_column(String, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String, nullable=False, default="medium")
    title: Mapped[str] = mapped_column(String, nullable=False, default="")
    description: Mapped[str] = mapped_column(String, nullable=False, default="")
    detail_json: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="active", index=True)
    source: Mapped[str] = mapped_column(String, nullable=False, default="scanner")
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String, nullable=True)
    hostname: Mapped[str | None] = mapped_column(String, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True)
    domain: Mapped[str | None] = mapped_column(String, nullable=True)
    url: Mapped[str | None] = mapped_column(String, nullable=True)
    tls_version: Mapped[str | None] = mapped_column(String, nullable=True)
    certificate_issuer: Mapped[str | None] = mapped_column(String, nullable=True)
    certificate_expiry: Mapped[str | None] = mapped_column(String, nullable=True)
    header_name: Mapped[str | None] = mapped_column(String, nullable=True)
    header_value: Mapped[str | None] = mapped_column(String, nullable=True)
    technology_name: Mapped[str | None] = mapped_column(String, nullable=True)
    technology_version: Mapped[str | None] = mapped_column(String, nullable=True)
    cloud_provider: Mapped[str | None] = mapped_column(String, nullable=True)
    cloud_bucket: Mapped[str | None] = mapped_column(String, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    metadata_json: Mapped[str | None] = mapped_column(String, nullable=True)
    first_seen: Mapped[str] = mapped_column(String, nullable=False)
    last_seen: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class ExposureHistoryModel(Base):
    __tablename__ = "exposure_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    exposure_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False)
    timestamp: Mapped[str] = mapped_column(String, nullable=False)
    previous_value: Mapped[str | None] = mapped_column(String, nullable=True)
    new_value: Mapped[str | None] = mapped_column(String, nullable=True)
    actor: Mapped[str] = mapped_column(String, nullable=False, default="system")


# ===========================================================================
#  Continuous Monitoring models  (Phase 20)
# ===========================================================================


class MonitorEventModel(Base):
    __tablename__ = "monitor_events"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    event_type: Mapped[str] = mapped_column(String, nullable=False, index=True)
    asset_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    assessment_id: Mapped[str | None] = mapped_column(String, nullable=True)
    source: Mapped[str] = mapped_column(String, nullable=False, default="monitor")
    title: Mapped[str] = mapped_column(String, nullable=False, default="")
    description: Mapped[str] = mapped_column(String, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String, nullable=False, default="info")
    context_json: Mapped[str | None] = mapped_column(String, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(String, nullable=True)
    timestamp: Mapped[str] = mapped_column(String, nullable=False, index=True)


class AlertModel(Base):
    __tablename__ = "monitor_alerts"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    rule_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String, nullable=False, default="")
    description: Mapped[str] = mapped_column(String, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String, nullable=False, default="medium", index=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="open", index=True)
    source_event_id: Mapped[str | None] = mapped_column(String, nullable=True)
    asset_id: Mapped[str | None] = mapped_column(String, nullable=True)
    assessment_id: Mapped[str | None] = mapped_column(String, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    acknowledged_at: Mapped[str | None] = mapped_column(String, nullable=True)
    resolved_at: Mapped[str | None] = mapped_column(String, nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String, nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String, nullable=True)


class RuleModel(Base):
    __tablename__ = "monitor_rules"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False, default="")
    event_type: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    conditions_json: Mapped[str | None] = mapped_column(String, nullable=True)
    alert_severity: Mapped[str] = mapped_column(String, nullable=False, default="medium")
    alert_title_template: Mapped[str] = mapped_column(String, nullable=False, default="")
    alert_description_template: Mapped[str] = mapped_column(String, nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    cooldown_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    notify_channels_json: Mapped[str | None] = mapped_column(String, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class CveEntryModel(Base):
    __tablename__ = "cve_entries"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    cve_code: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String, nullable=False, default="NONE", index=True)
    published_date: Mapped[str | None] = mapped_column(String, nullable=True)
    last_modified: Mapped[str | None] = mapped_column(String, nullable=True)
    cvss_data_json: Mapped[str | None] = mapped_column(String, nullable=True)
    epss_data_json: Mapped[str | None] = mapped_column(String, nullable=True)
    exploit_maturity: Mapped[str] = mapped_column(String, nullable=False, default="unknown")
    affected_products_json: Mapped[str | None] = mapped_column(String, nullable=True)
    references_json: Mapped[str | None] = mapped_column(String, nullable=True)
    vendor_advisories_json: Mapped[str | None] = mapped_column(String, nullable=True)
    weaknesses_json: Mapped[str | None] = mapped_column(String, nullable=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    kev_entry_json: Mapped[str | None] = mapped_column(String, nullable=True)
    threat_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, index=True)
    exploitability_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    priority_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    metadata_json: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class ThreatFeedModel(Base):
    __tablename__ = "threat_feeds"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    feed_type: Mapped[str] = mapped_column(String, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String, nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source_url: Mapped[str] = mapped_column(String, nullable=False, default="")
    entries: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_synced: Mapped[str] = mapped_column(String, nullable=False, default="")
    status: Mapped[str] = mapped_column(String, nullable=False, default="active")
    metadata_json: Mapped[str | None] = mapped_column(String, nullable=True)


class CopilotConversationModel(Base):
    __tablename__ = "copilot_conversations"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    title: Mapped[str] = mapped_column(String, nullable=False, default="New Investigation")
    owner: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    assessment_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    finding_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    asset_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    cve_id: Mapped[str | None] = mapped_column(String, nullable=True)
    alert_id: Mapped[str | None] = mapped_column(String, nullable=True)
    exposure_id: Mapped[str | None] = mapped_column(String, nullable=True)
    messages_json: Mapped[str | None] = mapped_column(String, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class InvestigationNoteModel(Base):
    __tablename__ = "investigation_notes"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    conversation_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    author: Mapped[str] = mapped_column(String, nullable=False, default="")
    pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    assessment_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    finding_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    tags_json: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class PlaybookModel(Base):
    __tablename__ = "playbooks"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    category: Mapped[str] = mapped_column(String, nullable=False, default="general")
    severity: Mapped[str] = mapped_column(String, nullable=False, default="medium")
    tags_json: Mapped[str | None] = mapped_column(String, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    trigger_json: Mapped[str] = mapped_column(String, nullable=False, default="{}")
    actions_json: Mapped[str] = mapped_column(String, nullable=False, default="[]")
    rollback_actions_json: Mapped[str] = mapped_column(String, nullable=False, default="[]")
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class ExecutionHistoryModel(Base):
    __tablename__ = "execution_history"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    playbook_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    playbook_name: Mapped[str] = mapped_column(String, nullable=False, default="")
    trigger_type: Mapped[str] = mapped_column(String, nullable=False, default="manual")
    trigger_entity_id: Mapped[str] = mapped_column(String, nullable=False, default="")
    status: Mapped[str] = mapped_column(String, nullable=False, default="pending")
    action_logs_json: Mapped[str | None] = mapped_column(String, nullable=True)
    started_at: Mapped[str] = mapped_column(String, nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    rolled_back: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)

    __table_args__ = (
        Index("ix_execution_history_status", "status"),
        Index("ix_execution_history_created", "created_at"),
    )


class PluginSdkManifestModel(Base):
    __tablename__ = "plugin_sdk_manifests"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    version: Mapped[str] = mapped_column(String, nullable=False, default="0.0.0")
    author: Mapped[str] = mapped_column(String, nullable=False, default="")
    website: Mapped[str] = mapped_column(String, nullable=False, default="")
    license: Mapped[str] = mapped_column(String, nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    category: Mapped[str] = mapped_column(String, nullable=False, default="other")
    entrypoint: Mapped[str] = mapped_column(String, nullable=False, default="")
    minimum_kingsec_version: Mapped[str] = mapped_column(String, nullable=False, default="0.0.0")
    permissions_json: Mapped[str | None] = mapped_column(String, nullable=True)
    dependencies_json: Mapped[str | None] = mapped_column(String, nullable=True)
    signature: Mapped[str] = mapped_column(String, nullable=False, default="")
    installed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    loaded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class WorkerModel(Base):
    __tablename__ = "workers"

    worker_id: Mapped[str] = mapped_column(String, primary_key=True)
    hostname: Mapped[str] = mapped_column(String, nullable=False)
    os: Mapped[str] = mapped_column(String, nullable=False, default="")
    cpu: Mapped[str] = mapped_column(String, nullable=False, default="")
    ram_mb: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    capabilities_json: Mapped[str | None] = mapped_column(String, nullable=True)
    current_jobs_json: Mapped[str | None] = mapped_column(String, nullable=True)
    health: Mapped[str] = mapped_column(String, nullable=False, default="healthy")
    last_heartbeat: Mapped[str] = mapped_column(String, nullable=False, default="")
    status: Mapped[str] = mapped_column(String, nullable=False, default="online", index=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class JobQueueEntryModel(Base):
    __tablename__ = "job_queue_entries"

    entry_id: Mapped[str] = mapped_column(String, primary_key=True)
    job_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    state: Mapped[str] = mapped_column(String, nullable=False, default="queued", index=True)
    payload: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target: Mapped[str] = mapped_column(String, nullable=False, default="", index=True)
    scanner_ids_json: Mapped[str | None] = mapped_column(String, nullable=True)
    assigned_worker_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_retries: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    error_message: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    started_at: Mapped[str | None] = mapped_column(String, nullable=True)
    completed_at: Mapped[str | None] = mapped_column(String, nullable=True)


class JobLeaseModel(Base):
    __tablename__ = "job_leases"

    lease_id: Mapped[str] = mapped_column(String, primary_key=True)
    job_id: Mapped[str] = mapped_column(String, nullable=False, index=True, unique=True)
    worker_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    acquired_at: Mapped[str] = mapped_column(String, nullable=False)
    expires_at: Mapped[str] = mapped_column(String, nullable=False)
    renewed_at: Mapped[str] = mapped_column(String, nullable=False, default="")
    released_at: Mapped[str | None] = mapped_column(String, nullable=True)


class IdentityProviderModel(Base):
    __tablename__ = "identity_providers"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    protocol: Mapped[str] = mapped_column(String, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="pending")
    issuer: Mapped[str] = mapped_column(String, nullable=False, default="")
    domain_hint: Mapped[str] = mapped_column(String, nullable=False, default="", index=True)
    role_mappings_json: Mapped[str | None] = mapped_column(String, nullable=True)
    group_mappings_json: Mapped[str | None] = mapped_column(String, nullable=True)
    jit_provisioning: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    auto_link_users: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    enforce_sso: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    metadata_xml: Mapped[str | None] = mapped_column(String, nullable=True)
    saml_config_json: Mapped[str | None] = mapped_column(String, nullable=True)
    oidc_config_json: Mapped[str | None] = mapped_column(String, nullable=True)
    ldap_config_json: Mapped[str | None] = mapped_column(String, nullable=True)
    oauth2_config_json: Mapped[str | None] = mapped_column(String, nullable=True)
    organization_id: Mapped[str] = mapped_column(String, nullable=False, default="")
    created_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)


class SSOSessionModel(Base):
    __tablename__ = "sso_sessions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    provider_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    external_user_id: Mapped[str] = mapped_column(String, nullable=False, default="")
    idp_session_id: Mapped[str] = mapped_column(String, nullable=False, default="")
    idp_assertion: Mapped[str] = mapped_column(Text, nullable=False, default="")
    attributes_json: Mapped[str | None] = mapped_column(String, nullable=True)
    session_index: Mapped[str] = mapped_column(String, nullable=False, default="")
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    expires_at: Mapped[str] = mapped_column(String, nullable=False, default="")
    last_activity: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class AccountLinkModel(Base):
    __tablename__ = "account_links"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    provider_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    external_user_id: Mapped[str] = mapped_column(String, nullable=False)
    external_username: Mapped[str] = mapped_column(String, nullable=False, default="")
    external_email: Mapped[str] = mapped_column(String, nullable=False, default="")
    linked_at: Mapped[str] = mapped_column(String, nullable=False)

    __table_args__ = (
        Index("ix_account_links_provider_user", "provider_id", "external_user_id", unique=True),
    )


class DeadLetterEntryModel(Base):
    __tablename__ = "dead_letter_entries"

    entry_id: Mapped[str] = mapped_column(String, primary_key=True)
    original_job_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    original_entry_id: Mapped[str] = mapped_column(String, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    payload: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target: Mapped[str] = mapped_column(String, nullable=False, default="")
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_at: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)


class AssessmentConcurrencySlotORM(Base):
    """A single-row counter enforcing `max_concurrent_assessments`
    (KSEC-87-02). Deliberately its own table, not a column bolted onto
    ``AssessmentModel`` - this counts across ALL assessment rows at once,
    which is a different kind of constraint than the per-row optimistic
    lock (`version`) pattern used for schedules/organizations/teams.
    Exactly one row exists (id=1, seeded by the creating migration).
    SqlAlchemyAssessmentConcurrencyRepository never reads active_count and
    decides separately whether to write - every mutation is a single
    conditional ``UPDATE ... WHERE active_count < :max`` (or `> 0` for
    release), so the check and the claim/release are one atomic
    statement, with no read-then-write gap for a concurrent caller to
    race.
    """

    __tablename__ = "assessment_concurrency_slots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    active_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
