"""Evidence and Recommendation — immutable value objects owned by findings.

Both are frozen: a piece of evidence or a recommendation is defined entirely by
its content and never changes once recorded. That immutability is what lets a
Finding safely expose them and what makes a Report a trustworthy snapshot.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from ._validation import ensure_non_empty, ensure_timezone_aware
from .enums import Severity


@dataclass(frozen=True, slots=True)
class Evidence:
    """Proof supporting a finding (an observation, response, payload, etc.)."""

    summary: str            # short: what this proves
    detail: str             # the raw supporting material
    collected_at: datetime  # when it was captured (timezone-aware)

    def __post_init__(self) -> None:
        ensure_non_empty(self.summary, "Evidence summary")
        ensure_non_empty(self.detail, "Evidence detail")
        ensure_timezone_aware(self.collected_at, "Evidence collected_at")

    @classmethod
    def create(cls, summary: str, detail: str) -> Evidence:
        """Create evidence stamped at the current UTC time."""
        return cls(summary=summary, detail=detail, collected_at=datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class Recommendation:
    """Remediation guidance for a finding."""

    title: str
    description: str
    priority: Severity      # how urgently this should be actioned

    def __post_init__(self) -> None:
        ensure_non_empty(self.title, "Recommendation title")
        ensure_non_empty(self.description, "Recommendation description")
        if not isinstance(self.priority, Severity):
            from .errors import InvariantViolation

            raise InvariantViolation("Recommendation priority must be a Severity")
