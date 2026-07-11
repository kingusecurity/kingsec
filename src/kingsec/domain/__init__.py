"""KingSec domain layer — pure business model, standard-library only.

This package has NO outward dependencies: no infrastructure, no application, no
shared kernel, no third-party libraries. Everything below is expressed in plain
Python so the core business rules can be understood and tested in isolation.

Public API
    Entities / aggregate
        Assessment, Finding, User
    Value objects
        AssessmentId, FindingId, Target, TargetType, Authorization,
        Evidence, Recommendation, Report, Verdict, FindingSummary
    Enums
        Severity, AssessmentStatus, FindingStatus, Role
    Errors
        DomainError, InvariantViolation, IllegalStateTransition,
        UserError, UserNotFoundError, InvalidCredentialsError,
        UserDisabledError, PasswordValidationError
"""

from __future__ import annotations

from .assessment import Assessment
from .authorization import Authorization
from .enums import AssessmentStatus, FindingStatus, Role, Severity
from .errors import DomainError, IllegalStateTransition, InvariantViolation
from .evidence import Evidence, Recommendation
from .finding import Finding
from .identifiers import AssessmentId, FindingId
from .report import FindingSummary, Report, Verdict
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
    "Assessment",
    "AssessmentId",
    "AssessmentStatus",
    "Authorization",
    "DomainError",
    "Evidence",
    "Finding",
    "FindingId",
    "FindingStatus",
    "FindingSummary",
    "IllegalStateTransition",
    "InvariantViolation",
    "InvalidCredentialsError",
    "PasswordValidationError",
    "Recommendation",
    "Report",
    "Role",
    "Severity",
    "Target",
    "TargetType",
    "User",
    "UserDisabledError",
    "UserError",
    "UserNotFoundError",
    "Verdict",
]
