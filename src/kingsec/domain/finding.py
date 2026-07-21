"""The Finding entity.

An *entity*, not a value object: it has an identity (``FindingId``) and a
lifecycle. Two Finding objects are "the same finding" if their ids match, even
if their evidence differs — so equality is by id, not by content.

Why a plain class rather than a dataclass?
    A dataclass generates an ``__init__`` that exposes every field as freely
    settable, which is exactly what we DON'T want for an entity with invariants.
    A plain class lets us keep state private and mutate it only through
    intention-revealing methods (``confirm``, ``add_evidence``) that enforce the
    rules. Value objects get dataclasses; entities get controlled mutation.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ._validation import ensure_non_empty, ensure_timezone_aware
from .enums import FindingStatus, Severity
from .errors import IllegalStateTransition, InvariantViolation
from .evidence import Evidence, Recommendation
from .identifiers import FindingId

# Which finding-status transitions are legal. An empty set means "terminal".
_ALLOWED_FINDING_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.OPEN: {FindingStatus.CONFIRMED, FindingStatus.FALSE_POSITIVE},
    FindingStatus.CONFIRMED: {FindingStatus.REMEDIATED, FindingStatus.FALSE_POSITIVE},
    FindingStatus.FALSE_POSITIVE: set(),
    FindingStatus.REMEDIATED: set(),
}


class Finding:
    """A single discovered issue within an assessment."""

    def __init__(
        self,
        finding_id: FindingId,
        title: str,
        description: str,
        severity: Severity,
        *,
        discovered_at: datetime | None = None,
    ) -> None:
        if not isinstance(finding_id, FindingId):
            raise InvariantViolation("finding_id must be a FindingId")
        if not isinstance(severity, Severity):
            raise InvariantViolation("severity must be a Severity")
        ensure_non_empty(title, "Finding title")
        ensure_non_empty(description, "Finding description")

        moment = discovered_at or datetime.now(UTC)
        ensure_timezone_aware(moment, "discovered_at")

        self._id = finding_id
        self._title = title
        self._description = description
        self._severity = severity
        self._status = FindingStatus.OPEN
        self._discovered_at = moment
        self._evidence: list[Evidence] = []
        self._recommendations: list[Recommendation] = []

    # --- factory -------------------------------------------------------------
    @classmethod
    def create(cls, title: str, description: str, severity: Severity) -> Finding:
        """Create a new OPEN finding with a freshly generated id."""
        return cls(FindingId.generate(), title, description, severity)

    @classmethod
    def reconstitute(
        cls,
        *,
        finding_id: FindingId,
        title: str,
        description: str,
        severity: Severity,
        status: FindingStatus,
        discovered_at: datetime,
        evidence: list[Evidence] | None = None,
        recommendations: list[Recommendation] | None = None,
    ) -> Finding:
        """Rebuild a Finding from stored state (persistence boundary).

        Bypasses lifecycle transitions — the caller (mapper) is trusted to
        provide a consistent state. Structural invariants (non-empty title,
        timezone-aware timestamps) are still enforced.
        """
        ensure_non_empty(title, "Finding title")
        ensure_non_empty(description, "Finding description")
        ensure_timezone_aware(discovered_at, "discovered_at")

        f = cls.__new__(cls)
        f._id = finding_id
        f._title = title
        f._description = description
        f._severity = severity
        f._status = status
        f._discovered_at = discovered_at
        f._evidence = list(evidence) if evidence is not None else []
        f._recommendations = list(recommendations) if recommendations is not None else []
        return f

    # --- read-only accessors -------------------------------------------------
    @property
    def id(self) -> FindingId:
        return self._id

    @property
    def title(self) -> str:
        return self._title

    @property
    def description(self) -> str:
        return self._description

    @property
    def severity(self) -> Severity:
        return self._severity

    @property
    def status(self) -> FindingStatus:
        return self._status

    @property
    def discovered_at(self) -> datetime:
        return self._discovered_at

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        # Return an immutable copy so callers cannot mutate our internal list.
        return tuple(self._evidence)

    @property
    def recommendations(self) -> tuple[Recommendation, ...]:
        return tuple(self._recommendations)

    # --- behaviour -----------------------------------------------------------
    def add_evidence(self, evidence: Evidence) -> None:
        """Attach supporting evidence. Not allowed once the finding is closed."""
        if not isinstance(evidence, Evidence):
            raise InvariantViolation("evidence must be an Evidence instance")
        if self._status.is_closed:
            raise IllegalStateTransition(
                f"cannot add evidence to a {self._status.value} finding",
                current=self._status,
            )
        self._evidence.append(evidence)

    def add_recommendation(self, recommendation: Recommendation) -> None:
        """Attach a remediation recommendation. Not allowed once closed."""
        if not isinstance(recommendation, Recommendation):
            raise InvariantViolation("recommendation must be a Recommendation")
        if self._status.is_closed:
            raise IllegalStateTransition(
                f"cannot add a recommendation to a {self._status.value} finding",
                current=self._status,
            )
        self._recommendations.append(recommendation)

    def confirm(self) -> None:
        """Mark an OPEN finding as CONFIRMED (a real, verified issue)."""
        self._transition_to(FindingStatus.CONFIRMED)

    def mark_false_positive(self) -> None:
        """Dismiss the finding as a false positive."""
        self._transition_to(FindingStatus.FALSE_POSITIVE)

    def mark_remediated(self) -> None:
        """Mark a CONFIRMED finding as fixed."""
        self._transition_to(FindingStatus.REMEDIATED)

    # --- internals -----------------------------------------------------------
    def _transition_to(self, new_status: FindingStatus) -> None:
        allowed = _ALLOWED_FINDING_TRANSITIONS[self._status]
        if new_status not in allowed:
            raise IllegalStateTransition(
                f"cannot move finding from {self._status.value} to {new_status.value}",
                current=self._status,
                attempted=new_status,
            )
        self._status = new_status

    # --- identity ------------------------------------------------------------
    def __eq__(self, other: object) -> bool:
        # Entity equality is by identity, not by attributes.
        return isinstance(other, Finding) and other._id == self._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return f"Finding(id={self._id.value!r}, severity={self._severity.name}, status={self._status.value})"
