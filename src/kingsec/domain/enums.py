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
    COMPLETED_WITH_GAPS = "completed_with_gaps"
    CANCELLED = "cancelled"
    FAILED = "failed"

    @property
    def is_terminal(self) -> bool:
        """True if no further transitions are allowed from this state."""
        return self in {
            AssessmentStatus.COMPLETED,
            AssessmentStatus.COMPLETED_WITH_GAPS,
            AssessmentStatus.CANCELLED,
            AssessmentStatus.FAILED,
        }


class ScannerRunState(Enum):
    """Every state a single scanner's run through one assessment can be in.

    Phase 2A Correction 3: replaces a raw ``str`` field on
    ``ScannerRunSummary``/``ScannerProgress``, where "terminal" was
    convention only — exactly how a scanner could be left at PENDING
    forever with nothing structurally preventing it. Terminality is a
    property of the enum itself, not a hand-maintained list.

    Lives in the domain layer (not application, where the execution
    tracker that produces it lives) because ``ScannerRunSummary`` below
    is a domain object, and domain may not import from application.
    """

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED_INCOMPATIBLE = "skipped_incompatible"
    SKIPPED_BINARY_MISSING = "skipped_binary_missing"
    SKIPPED_ASSET_MISSING = "skipped_asset_missing"

    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL_SCANNER_RUN_STATES

    @property
    def is_success(self) -> bool:
        return self is ScannerRunState.SUCCEEDED

    @property
    def is_skip(self) -> bool:
        return self in (
            ScannerRunState.SKIPPED_INCOMPATIBLE,
            ScannerRunState.SKIPPED_BINARY_MISSING,
            ScannerRunState.SKIPPED_ASSET_MISSING,
        )


_TERMINAL_SCANNER_RUN_STATES = frozenset(
    {
        ScannerRunState.SUCCEEDED,
        ScannerRunState.FAILED,
        ScannerRunState.TIMED_OUT,
        ScannerRunState.SKIPPED_INCOMPATIBLE,
        ScannerRunState.SKIPPED_BINARY_MISSING,
        ScannerRunState.SKIPPED_ASSET_MISSING,
    }
)


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
