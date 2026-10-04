"""Audit entry value object and action taxonomy — pure domain, no framework dependencies.

The audit trail is an immutable, append-only security record of every
meaningful action in KingSec. ``AuditEntry`` is a *frozen* dataclass:
once constructed, it cannot be modified. This is a domain invariant, not
an implementation detail.

``AuditAction`` enumerates every auditable action. Adding a new action
requires updating this enum — the type system catches missing cases.

Design decisions:
    - AuditEntry is a VALUE OBJECT (no identity, no mutability). The
      database-assigned ``id`` is a persistence concern set by the
      repository, not the domain.
    - Metadata is an optional dict for extensibility (e.g. extra context
      specific to an action). It must be JSON-serializable.
    - Success/failure is captured explicitly. A failed login is as
      important as a successful one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class AuditAction(StrEnum):
    """Every auditable action in KingSec.

    Using ``str, Enum`` so values are human-readable in logs and DB
    without needing a lookup table.
    """

    # Authentication
    LOGIN = "login"
    FAILED_LOGIN = "failed_login"
    LOGOUT = "logout"
    TOKEN_REFRESHED = "token_refreshed"  # nosec B105 — audit event type name, not a credential

    # User management
    USER_REGISTERED = "user_registered"
    # kingsec-bootstrap CLI (Phase 3) - distinct from USER_REGISTERED so an
    # operator scanning audit logs for admin-creation events finds a
    # self-describing entry, not a USER_REGISTERED row that needs
    # filtering by role.
    ADMIN_BOOTSTRAPPED = "admin_bootstrapped"
    ROLE_CHANGED = "role_changed"
    PASSWORD_CHANGED = "password_changed"  # nosec B105 — audit event type name, not a credential
    USER_DEACTIVATED = "user_deactivated"
    USER_ACTIVATED = "user_activated"
    PASSWORD_RESET = "password_reset"  # nosec B105 — audit event type name, not a credential

    # Assessment lifecycle
    ASSESSMENT_CREATED = "assessment_created"
    ASSESSMENT_STARTED = "assessment_started"
    ASSESSMENT_COMPLETED = "assessment_completed"
    ASSESSMENT_FAILED = "assessment_failed"
    ASSESSMENT_CANCELLED = "assessment_cancelled"
    ASSESSMENT_DELETED = "assessment_deleted"
    ASSESSMENT_SUBMITTED = "assessment_submitted"

    # Reports
    REPORT_GENERATED = "report_generated"

    # Authorization failures
    AUTHORIZATION_FAILURE = "authorization_failure"

    # Authorization grants (Phase 4: scope enforcement)
    AUTHORIZATION_GRANT_CREATED = "authorization_grant_created"
    AUTHORIZATION_GRANT_REVOKED = "authorization_grant_revoked"
    # A CreateAssessment.execute() call was refused because no active
    # grant covers the target at a ScannerSurfaceTier the profile's
    # scanners would actually touch - see AuthorizationScopeError.
    SCOPE_CHECK_REFUSED = "scope_check_refused"
    # An admin used the scope-check override to proceed despite
    # SCOPE_CHECK_REFUSED's own refusal - distinct from it so an audit
    # query can find every override separately from every refusal, not
    # just infer overrides from the absence of a matching refusal entry.
    SCOPE_CHECK_OVERRIDDEN = "scope_check_overridden"

    # Schedule lifecycle
    SCHEDULE_CREATED = "schedule_created"
    SCHEDULE_UPDATED = "schedule_updated"
    SCHEDULE_DELETED = "schedule_deleted"
    SCHEDULE_TRIGGERED = "schedule_triggered"
    SCHEDULE_PAUSED = "schedule_paused"
    SCHEDULE_RESUMED = "schedule_resumed"
    SCHEDULE_ENABLED = "schedule_enabled"
    SCHEDULE_DISABLED = "schedule_disabled"
    # KSEC-100-01: a scheduled occurrence in CREATING/SUBMITTING could not
    # be safely, automatically resolved (no linked assessment, an ambiguous
    # number of linked assessments, an unexpected assessment status, or a
    # SUBMITTING state that cannot be recovered without an execution
    # ledger). Distinct from SCHEDULE_TRIGGERED so an operator/audit query
    # can tell "this ran" apart from "this could not be confirmed to run".
    SCHEDULE_OCCURRENCE_UNRESOLVED = "schedule_occurrence_unresolved"

    # Assessment execution ledger inspection
    # KSEC-103-01: an administrator queried the durable execution ledger
    # (list or single lookup). Distinct from any lifecycle action above -
    # this is a READ, never a state transition; recorded as a best-effort
    # summary per request, not per row, to avoid audit-log noise.
    EXECUTION_INSPECTED = "execution_inspected"
    # KSEC-105-01: an administrator attempted to reconcile a durable
    # execution record. Recorded for every attempt that reaches the
    # application use case, whether it actually mutated the ledger,
    # found it already correctly resolved (idempotent no-op), or was
    # rejected for insufficient evidence - `success`/`reason`/`metadata`
    # (see the use case) distinguish which. Never emitted claiming a
    # result that did not actually happen (KSEC-105-01 Step 20).
    EXECUTION_RECONCILED = "execution_reconciled"

    # Notifications
    NOTIFICATION_SENT = "notification_sent"
    NOTIFICATION_FAILED = "notification_failed"
    NOTIFICATION_RETRIED = "notification_retried"
    NOTIFICATION_READ = "notification_read"
    NOTIFICATION_DELETED = "notification_deleted"

    # Plugin lifecycle
    PLUGIN_INSTALLED = "plugin_installed"
    PLUGIN_UPDATED = "plugin_updated"
    PLUGIN_UNINSTALLED = "plugin_uninstalled"
    PLUGIN_ENABLED = "plugin_enabled"
    PLUGIN_DISABLED = "plugin_disabled"
    PLUGIN_VALIDATED = "plugin_validated"
    PLUGIN_ROLLED_BACK = "plugin_rolled_back"

    # Agent lifecycle
    AGENT_REGISTERED = "agent_registered"
    AGENT_HEARTBEAT = "agent_heartbeat"
    AGENT_DISABLED = "agent_disabled"
    AGENT_ENABLED = "agent_enabled"
    AGENT_REMOVED = "agent_removed"
    AGENT_JOB_ASSIGNED = "agent_job_assigned"
    AGENT_JOB_COMPLETED = "agent_job_completed"
    AGENT_JOB_FAILED = "agent_job_failed"

    # Pipeline lifecycle
    PIPELINE_STARTED = "pipeline_started"
    PIPELINE_ADVANCED = "pipeline_advanced"
    PIPELINE_CANCELLED = "pipeline_cancelled"
    PIPELINE_PAUSED = "pipeline_paused"
    PIPELINE_RESUMED = "pipeline_resumed"
    PIPELINE_RETRIED = "pipeline_retried"

    # Backup lifecycle
    BACKUP_CREATED = "backup_created"
    BACKUP_COMPLETED = "backup_completed"
    BACKUP_FAILED = "backup_failed"
    BACKUP_RESTORED = "backup_restored"
    BACKUP_DELETED = "backup_deleted"
    SNAPSHOT_CREATED = "snapshot_created"
    SNAPSHOT_RESTORED = "snapshot_restored"

    # Production / Health
    # Integration lifecycle
    INTEGRATION_CONNECTED = "integration_connected"
    INTEGRATION_DISCONNECTED = "integration_disconnected"
    INTEGRATION_TEST_FAILED = "integration_test_failed"

    # AI provider settings
    AI_PROVIDER_CONFIGURED = "ai_provider_configured"
    AI_PROVIDER_TEST_FAILED = "ai_provider_test_failed"
    WEBHOOK_SENT = "webhook_sent"
    EMAIL_SENT = "email_sent"
    TICKET_CREATED = "ticket_created"
    EXPORT_COMPLETED = "export_completed"
    CONNECTION_FAILED = "connection_failed"

    # License lifecycle
    LICENSE_ACTIVATED = "license_activated"
    LICENSE_EXPIRED = "license_expired"
    LICENSE_RENEWED = "license_renewed"
    LICENSE_VALIDATION_FAILED = "license_validation_failed"
    LICENSE_DEACTIVATED = "license_deactivated"
    EDITION_CHANGED = "edition_changed"

    # Compliance
    COMPLIANCE_REPORT_GENERATED = "compliance_report_generated"
    COMPLIANCE_EXPORTED = "compliance_exported"

    # AI Copilot
    COPILOT_ASK = "copilot_ask"
    COPILOT_CONVERSATION_DELETED = "copilot_conversation_deleted"
    NOTE_CREATED = "note_created"
    NOTE_PINNED = "note_pinned"
    NOTE_UNPINNED = "note_unpinned"
    NOTE_DELETED = "note_deleted"

    HEALTH_CHECK = "health_check"
    LIVENESS_CHECK = "liveness_check"
    READINESS_CHECK = "readiness_check"
    SYSTEM_STOPPED = "system_stopped"
    SYSTEM_RESTARTED = "system_restarted"
    METRICS_COLLECTED = "metrics_collected"
    STARTUP_VALIDATED = "startup_validated"


@dataclass(frozen=True)
class AuditEntry:
    """An immutable audit record.

    Attributes:
        action: The auditable action performed.
        resource_type: The type of resource affected (e.g. "assessment", "user", "report").
        resource_id: The ID of the affected resource (optional — some actions
            have no specific resource, e.g. login).
        success: Whether the action succeeded.
        reason: Explanation for failure (optional — only set on failures).
        timestamp: When the action occurred (UTC, ISO-8601).
        user_id: ID of the user who performed the action (optional — anonymous actions).
        username: Username of the actor (optional — denormalized for query convenience).
        role: Role of the actor at the time of the action (optional).
        ip_address: Client IP address (optional — set by web adapter).
        user_agent: Client user-agent string (optional — set by web adapter).
        correlation_id: Request correlation ID (optional — set by web adapter).
        metadata: Additional JSON-serializable context (optional).
    """

    action: AuditAction
    resource_type: str = ""
    resource_id: str = ""
    success: bool = True
    reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    user_id: str = ""
    username: str = ""
    role: str = ""
    ip_address: str = ""
    user_agent: str = ""
    correlation_id: str = ""
    metadata: dict[str, object] = field(default_factory=dict)
