"""KingSec domain layer — pure business model, standard-library only.

This package has NO outward dependencies: no infrastructure, no application, no
shared kernel, no third-party libraries. Everything below is expressed in plain
Python so the core business rules can be understood and tested in isolation.

Public API
    Entities / aggregate
        Assessment, Finding, User
    Value objects
        AssessmentId, FindingId, Target, TargetType, Authorization,
        Evidence, Recommendation, Report, Verdict, FindingSummary,
        AuditEntry, ScannerId, ScannerPluginMetadata, ScannerCapability,
        PluginConfig, PluginAvailability, ScannerResult
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
from .authorization import Authorization
from .enums import AssessmentStatus, FindingStatus, Role, Severity
from .errors import DomainError, IllegalStateTransition, InvariantViolation
from .evidence import Evidence, Recommendation
from .finding import Finding
from .identifiers import AssessmentId, FindingId
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
    "ApiKey",
    "ApiKeyScope",
    "ApiKeyStatus",
    "Assessment",
    "AssessmentId",
    "AssessmentStatus",
    "AuditAction",
    "AuditEntry",
    "Authorization",
    "DomainError",
    "Evidence",
    "Finding",
    "FindingId",
    "FindingStatus",
    "FindingSummary",
    "IllegalStateTransition",
    "InvalidCredentialsError",
    "InvariantViolation",
    "OutputFormat",
    "PasswordValidationError",
    "PluginAvailability",
    "PluginConfig",
    "Recommendation",
    "Report",
    "Role",
    "ScanCategory",
    "ScannerCapability",
    "ScannerId",
    "ScannerPluginMetadata",
    "ScannerResult",
    "Severity",
    "Target",
    "TargetType",
    "User",
    "UserDisabledError",
    "UserError",
    "UserNotFoundError",
    "Verdict",
]
