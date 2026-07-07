"""Enumerations for the domain: severity and lifecycle statuses.

``Severity`` is an ``IntEnum`` so severities have a natural order — we can call
``max(...)`` over findings to compute an overall risk level, and compare with
``>=``. The other enums are plain ``Enum`` (their members have no ordering) but
expose helper properties that encode domain rules (which states are terminal).
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
