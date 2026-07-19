"""Enumerations for the domain: severity, lifecycle statuses, and user roles.

``Severity`` is an ``IntEnum`` so severities have a natural order — we can call
``max(...)`` over findings to compute an overall risk level, and compare with
``>=``. The other enums are plain ``Enum`` (their members have no ordering) but
expose helper properties that encode domain rules (which states are terminal).

``Role`` is an ``IntEnum`` so role hierarchy comparisons work naturally:
``Role.ADMIN >= Role.ANALYST`` is True, enabling permission checks without
explicit mapping tables.
"""

from __future__ import annotations

from enum import Enum, IntEnum


class Severity(IntEnum):
    """Risk severity, ordered from least to most severe."""

    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        """A capitalised, human-friendly label for reports/verdicts."""
        return self.name.capitalize()


class AssessmentStatus(Enum):
    """The lifecycle state of an assessment (milestone-based, not a percentage)."""

    DRAFT = "draft"
    AUTHORIZED = "authorized"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"

    @property
    def is_terminal(self) -> bool:
        """True if no further transitions are allowed from this state."""
        return self in {
            AssessmentStatus.COMPLETED,
            AssessmentStatus.CANCELLED,
            AssessmentStatus.FAILED,
        }


class FindingStatus(Enum):
    """The lifecycle state of a single finding."""

    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"

    @property
    def is_closed(self) -> bool:
        """True once a finding is settled and should not accrue new evidence."""
        return self in {FindingStatus.FALSE_POSITIVE, FindingStatus.REMEDIATED}


class Role(IntEnum):
    """User roles, ordered from least to most privileged.

    The integer ordering enables natural hierarchy checks:
        ``Role.ADMIN >= Role.ANALYST`` is True.

    Permission model:
        - Admin: full system access, user management, all operations
        - Analyst: create/modify assessments, generate reports, read access
        - Viewer: read-only access to assessments and reports
    """

    VIEWER = 10
    ANALYST = 20
    ADMIN = 30

    @property
    def label(self) -> str:
        """A capitalised, human-friendly label."""
        return self.name.capitalize()

    def has_permission(self, required: Role) -> bool:
        """Check if this role has at least the required privilege level."""
        return self >= required
