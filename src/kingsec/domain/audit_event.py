"""Enterprise audit event — immutable domain entity for security logging."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class AuditAction(str, Enum):
    """Every auditable action in KingSec (enterprise enumeration)."""

    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    TOKEN_REFRESHED = "token_refreshed"
    PASSWORD_CHANGED = "password_changed"
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
    REFRESH_TOKEN_REPLAY_DETECTED = "refresh_token_replay_detected"
    SECRET_CREATED = "secret_created"
    SECRET_DELETED = "secret_deleted"
    SECRET_ROTATED = "secret_rotated"
    SECRET_RETRIEVED = "secret_retrieved"


class AuditSeverity(str, Enum):
    """Severity level of an audit event."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AuditOutcome(str, Enum):
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
