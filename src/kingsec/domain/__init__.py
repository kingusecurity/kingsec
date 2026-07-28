"""KingSec domain layer — pure business model, standard-library only.

This package has NO outward dependencies: no infrastructure, no application, no
shared kernel, no third-party libraries. Everything below is expressed in plain
Python so the core business rules can be understood and tested in isolation.

Public API
    Entities / aggregate
        Assessment, Finding, User, AuditEvent
    Value objects
        AssessmentId, FindingId, AuditEventId, Target, TargetType,
        Authorization, Evidence, Recommendation, Report, Verdict,
        FindingSummary, AuditEntry, ScannerId, ScannerPluginMetadata,
        ScannerCapability, PluginConfig, PluginAvailability, ScannerResult
    Enums
        ApiKeyStatus, ApiKeyScope, Severity, AssessmentStatus,
        FindingStatus, Role, AuditAction, AuditOutcome, AuditSeverity,
        ScanCategory, OutputFormat
    Enums
        ApiKeyStatus, ApiKeyScope, Severity, AssessmentStatus,
        FindingStatus, Role, AuditAction, ScanCategory, OutputFormat
    Errors
        DomainError, InvariantViolation, IllegalStateTransition,
        UserError, UserNotFoundError, InvalidCredentialsError,
        UserDisabledError, PasswordValidationError
"""

from __future__ import annotations

from .api_key import ApiKey, ApiKeyScope, ApiKeyStatus
from .assessment import Assessment
from .audit import AuditAction, AuditEntry
from .audit_event import AuditEvent, AuditEventId, AuditOutcome, AuditSeverity
from .authorization import Authorization
from .backup import (
    BackupId,
    BackupMetadata,
    BackupSnapshot,
    BackupStatus,
    BackupType,
    RestoreOperation,
    RetentionPolicy,
)
from .enums import AssessmentStatus, FindingStatus, Role, Severity
from .errors import DomainError, IllegalStateTransition, InvariantViolation
from .evidence import Evidence, Recommendation
from .finding import Finding
from .identifiers import AssessmentId, FindingId
from .integration import (
    DeliveryRecord,
    DeliveryStatus,
    IntegrationConfig,
    IntegrationStatus,
    IntegrationType,
    SIEMBatchResult,
    TicketReference,
    WebhookEventType,
)
from .mfa import MfaRecoveryCode, MfaSecret, MfaStatus, RecoveryCodeStatus
from .pipeline import (
    PIPELINE_ORDER,
    PipelineExecution,
    PipelineId,
    PipelineResult,
    PipelineStage,
    PipelineState,
)
from .rate_limit import (
    AccountLockout,
    LockoutPolicy,
    RateLimitBucket,
    RateLimitDecision,
    RateLimitExceeded,
    RateLimitGroup,
    RateLimitKeyType,
    RateLimitPolicy,
)
from .report import FindingSummary, Report, Verdict
from .scanner import (
    OutputFormat,
    PluginAvailability,
    PluginConfig,
    ScanCategory,
    ScannerCapability,
    ScannerId,
    ScannerPluginMetadata,
    ScannerResult,
)
from .schedule import (
    RetryPolicy,
    RetryStrategy,
    ScanSchedule,
    ScheduleId,
    ScheduleStatus,
    ScheduleType,
)
from .secret import SecretId, SecretMetadata, SecretType
from .session import (
    DeviceInfo,
    Session,
    SessionId,
    SessionStatus,
    SessionType,
)
from .system_health import (
    DependencyHealth,
    HealthCheck,
    HealthStatus,
    LivenessReport,
    ReadinessReport,
    ResourceUsage,
    ServiceStatus,
    StartupCheck,
    SystemMetrics,
)
from .target import Target, TargetType
from .user import (
    InvalidCredentialsError,
    PasswordValidationError,
    User,
    UserDisabledError,
    UserError,
    UserNotFoundError,
)

__all__ = [
    "PIPELINE_ORDER",
    "AccountLockout",
    "ApiKey",
    "ApiKeyScope",
    "ApiKeyStatus",
    "Assessment",
    "AssessmentId",
    "AssessmentStatus",
    "AuditAction",
    "AuditEntry",
    "AuditEvent",
    "AuditEventId",
    "AuditOutcome",
    "AuditSeverity",
    "Authorization",
    "BackupId",
    "BackupMetadata",
    "BackupSnapshot",
    "BackupStatus",
    "BackupType",
    "DeliveryRecord",
    "DeliveryStatus",
    "DependencyHealth",
    "DeviceInfo",
    "DomainError",
    "Evidence",
    "Finding",
    "FindingId",
    "FindingStatus",
    "FindingSummary",
    "HealthCheck",
    "HealthStatus",
    "IllegalStateTransition",
    "IntegrationConfig",
    "IntegrationStatus",
    "IntegrationType",
    "InvalidCredentialsError",
    "InvariantViolation",
    "LivenessReport",
    "LockoutPolicy",
    "MfaRecoveryCode",
    "MfaSecret",
    "MfaStatus",
    "OutputFormat",
    "PasswordValidationError",
    "PipelineExecution",
    "PipelineId",
    "PipelineResult",
    "PipelineStage",
    "PipelineState",
    "PluginAvailability",
    "PluginConfig",
    "RateLimitBucket",
    "RateLimitDecision",
    "RateLimitExceeded",
    "RateLimitGroup",
    "RateLimitKeyType",
    "RateLimitPolicy",
    "ReadinessReport",
    "Recommendation",
    "RecoveryCodeStatus",
    "Report",
    "ResourceUsage",
    "RestoreOperation",
    "RetentionPolicy",
    "RetryPolicy",
    "RetryStrategy",
    "Role",
    "SIEMBatchResult",
    "ScanCategory",
    "ScanSchedule",
    "ScannerCapability",
    "ScannerId",
    "ScannerPluginMetadata",
    "ScannerResult",
    "ScheduleId",
    "ScheduleStatus",
    "ScheduleType",
    "SecretId",
    "SecretMetadata",
    "SecretType",
    "ServiceStatus",
    "Session",
    "SessionId",
    "SessionStatus",
    "SessionType",
    "Severity",
    "StartupCheck",
    "SystemMetrics",
    "Target",
    "TargetType",
    "TicketReference",
    "User",
    "UserDisabledError",
    "UserError",
    "UserNotFoundError",
    "Verdict",
    "WebhookEventType",
]
