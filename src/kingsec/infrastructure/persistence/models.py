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

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
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
    """A discovered network asset."""

    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    hostname: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    operating_system: Mapped[str | None] = mapped_column(String, nullable=True)
    owner: Mapped[str | None] = mapped_column(String, nullable=True)
    criticality: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[str] = mapped_column(String, nullable=False)  # ISO-8601

    findings: Mapped[list[FindingModel]] = relationship(
        foreign_keys=[FindingModel.asset_id],
        lazy="selectin",
    )


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
