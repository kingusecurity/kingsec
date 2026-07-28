"""Enterprise audit event — immutable domain entity for security logging."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class AuditAction(StrEnum):
    """Every auditable action in KingSec (enterprise enumeration)."""

    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    TOKEN_REFRESHED = "token_refreshed"  # nosec B105 — audit event type name, not a credential
    PASSWORD_CHANGED = "password_changed"  # nosec B105 — audit event type name, not a credential
    API_KEY_CREATED = "api_key_created"
    API_KEY_ROTATED = "api_key_rotated"
    API_KEY_DELETED = "api_key_deleted"
    JOB_CREATED = "job_created"
    JOB_CANCELLED = "job_cancelled"
    SCAN_EXECUTED = "scan_executed"
    REPORT_GENERATED = "report_generated"
    REPORT_DOWNLOADED = "report_downloaded"
    PERMISSION_DENIED = "permission_denied"
    AUTHENTICATION_FAILURE = "authentication_failure"
    USER_REGISTERED = "user_registered"
    ASSESSMENT_CREATED = "assessment_created"
    ASSESSMENT_STARTED = "assessment_started"
    ASSESSMENT_COMPLETED = "assessment_completed"
    ASSESSMENT_FAILED = "assessment_failed"
    ASSESSMENT_CANCELLED = "assessment_cancelled"
    ASSESSMENT_DELETED = "assessment_deleted"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    BRUTE_FORCE_DETECTED = "brute_force_detected"
    SESSION_CREATED = "session_created"
    SESSION_REFRESHED = "session_refreshed"
    SESSION_REVOKED = "session_revoked"
    LOGOUT_ALL = "logout_all"
    CONCURRENT_SESSION_LIMIT_EXCEEDED = "concurrent_session_limit_exceeded"
    REFRESH_TOKEN_REPLAY_DETECTED = "refresh_token_replay_detected"  # nosec B105 — audit event type name, not a credential
    SECRET_CREATED = "secret_created"  # nosec B105 — audit event type name, not a credential
    SECRET_DELETED = "secret_deleted"  # nosec B105 — audit event type name, not a credential
    SECRET_ROTATED = "secret_rotated"  # nosec B105 — audit event type name, not a credential
    SECRET_RETRIEVED = "secret_retrieved"  # nosec B105 — audit event type name, not a credential
    NOTIFICATION_SENT = "notification_sent"
    NOTIFICATION_FAILED = "notification_failed"
    NOTIFICATION_RETRIED = "notification_retried"
    NOTIFICATION_READ = "notification_read"
    NOTIFICATION_DELETED = "notification_deleted"
    PLUGIN_INSTALLED = "plugin_installed"
    PLUGIN_UPDATED = "plugin_updated"
    PLUGIN_UNINSTALLED = "plugin_uninstalled"
    PLUGIN_ENABLED = "plugin_enabled"
    PLUGIN_DISABLED = "plugin_disabled"
    PLUGIN_VALIDATED = "plugin_validated"
    PLUGIN_ROLLED_BACK = "plugin_rolled_back"
    AGENT_REGISTERED = "agent_registered"
    AGENT_HEARTBEAT = "agent_heartbeat"
    AGENT_DISABLED = "agent_disabled"
    AGENT_ENABLED = "agent_enabled"
    AGENT_REMOVED = "agent_removed"
    AGENT_JOB_ASSIGNED = "agent_job_assigned"
    AGENT_JOB_COMPLETED = "agent_job_completed"
    AGENT_JOB_FAILED = "agent_job_failed"

    # Integration lifecycle
    INTEGRATION_CONNECTED = "integration_connected"
    INTEGRATION_DISCONNECTED = "integration_disconnected"
    INTEGRATION_TEST_FAILED = "integration_test_failed"
    WEBHOOK_SENT = "webhook_sent"
    EMAIL_SENT = "email_sent"
    TICKET_CREATED = "ticket_created"
    EXPORT_COMPLETED = "export_completed"
    CONNECTION_FAILED = "connection_failed"


class AuditSeverity(StrEnum):
    """Severity level of an audit event."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AuditOutcome(StrEnum):
    """Outcome of an auditable action."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


@dataclass(frozen=True)
class AuditEventId:
    """Value object wrapping a UUID string for audit event identity."""

    value: str

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class AuditEvent:
    """An immutable enterprise audit event.

    This is a domain entity (has identity via ``id``) and is immutable.
    Once created, its fields cannot be changed — this is a domain invariant.
    """

    id: AuditEventId
    timestamp: str
    actor_id: str
    actor_type: str
    username: str
    ip_address: str
    user_agent: str
    request_id: str
    action: AuditAction
    resource_type: str
    resource_id: str
    outcome: AuditOutcome
    severity: AuditSeverity
    message: str
    metadata: dict[str, object] = field(default_factory=dict)
