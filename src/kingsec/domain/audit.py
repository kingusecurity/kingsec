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
from enum import Enum


class AuditAction(str, Enum):
    """Every auditable action in KingSec.

    Using ``str, Enum`` so values are human-readable in logs and DB
    without needing a lookup table.
    """

    # Authentication
    LOGIN = "login"
    FAILED_LOGIN = "failed_login"
    LOGOUT = "logout"
    TOKEN_REFRESHED = "token_refreshed"

    # User management
    USER_REGISTERED = "user_registered"
    PASSWORD_CHANGED = "password_changed"

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

    # Schedule lifecycle
    SCHEDULE_CREATED = "schedule_created"
    SCHEDULE_UPDATED = "schedule_updated"
    SCHEDULE_DELETED = "schedule_deleted"
    SCHEDULE_TRIGGERED = "schedule_triggered"
    SCHEDULE_PAUSED = "schedule_paused"
    SCHEDULE_RESUMED = "schedule_resumed"
    SCHEDULE_ENABLED = "schedule_enabled"
    SCHEDULE_DISABLED = "schedule_disabled"

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
