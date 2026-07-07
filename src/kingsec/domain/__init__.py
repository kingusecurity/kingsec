"""KingSec domain layer — pure business model, standard-library only.

This package has NO outward dependencies: no infrastructure, no application, no
shared kernel, no third-party libraries. Everything below is expressed in plain
Python so the core business rules can be understood and tested in isolation.

Public API
    Entities / aggregate
        Assessment, Finding
    Value objects
        AssessmentId, FindingId, Target, TargetType, Authorization,
        Evidence, Recommendation, Report, Verdict, FindingSummary
    Enums
        Severity, AssessmentStatus, FindingStatus
    Errors
        DomainError, InvariantViolation, IllegalStateTransition
"""

from __future__ import annotations

from .assessment import Assessment
from .authorization import Authorization
from .enums import AssessmentStatus, FindingStatus, Severity
from .errors import DomainError, IllegalStateTransition, InvariantViolation
from .evidence import Evidence, Recommendation
from .finding import Finding
from .identifiers import AssessmentId, FindingId
from .report import FindingSummary, Report, Verdict
from .target import Target, TargetType

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
    "Recommendation",
    "Report",
    "Severity",
    "Target",
    "TargetType",
    "Verdict",
]
