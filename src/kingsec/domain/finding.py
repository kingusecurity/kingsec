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
from .enums import FindingStatus, Severity, SeverityDemotionReason
from .errors import IllegalStateTransition, InvariantViolation
from .evidence import Evidence, Recommendation
from .identifiers import FindingId


def _ensure_valid_cvss_score(score: float | None) -> None:
    """CVSS scores are 0.0-10.0 by definition (both v3.x and v4.0). A value
    outside that range means a parser bug upstream, not real scanner data -
    fail loudly rather than carry a nonsensical score into a report."""
    if score is not None and not (0.0 <= score <= 10.0):
        raise InvariantViolation(f"cvss_score must be between 0.0 and 10.0, got {score!r}")


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
        cve_ids: tuple[str, ...] = (),
        cwe_ids: tuple[str, ...] = (),
        cvss_score: float | None = None,
        cvss_vector: str | None = None,
        original_severity: Severity | None = None,
        demotion_reason: SeverityDemotionReason | None = None,
    ) -> None:
        if not isinstance(finding_id, FindingId):
            raise InvariantViolation("finding_id must be a FindingId")
        if not isinstance(severity, Severity):
            raise InvariantViolation("severity must be a Severity")
        ensure_non_empty(title, "Finding title")
        ensure_non_empty(description, "Finding description")
        _ensure_valid_cvss_score(cvss_score)
        if (original_severity is None) != (demotion_reason is None):
            raise InvariantViolation(
                "original_severity and demotion_reason must be set together, or not at all"
            )

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
        self._cve_ids = tuple(cve_ids)
        self._cwe_ids = tuple(cwe_ids)
        self._cvss_score = cvss_score
        self._cvss_vector = cvss_vector
        self._original_severity = original_severity
        self._demotion_reason = demotion_reason

    # --- factory -------------------------------------------------------------
    @classmethod
    def create(
        cls,
        title: str,
        description: str,
        severity: Severity,
        *,
        cve_ids: tuple[str, ...] = (),
        cwe_ids: tuple[str, ...] = (),
        cvss_score: float | None = None,
        cvss_vector: str | None = None,
        original_severity: Severity | None = None,
        demotion_reason: SeverityDemotionReason | None = None,
    ) -> Finding:
        """Create a new OPEN finding with a freshly generated id.

        cve_ids/cwe_ids/cvss_score/cvss_vector are optional: only scanners
        that genuinely correlate to CVE data (Nuclei, Trivy) pass them.
        Scanners with no correlation source (e.g. Nmap's raw port/service
        banners) simply omit them, and the finding carries no CVE data -
        never fabricated, never guessed.

        original_severity/demotion_reason (Phase 2B-c Priority 1b) are set
        together, only when a scanner's own classifier demoted this
        finding's severity below what path/status-only scoring would have
        assigned (e.g. ffuf/gobuster's baseline-shape or content-type
        heuristics) - ``severity`` is always the FINAL, already-demoted
        value; ``original_severity`` records what it would have been.
        """
        return cls(
            FindingId.generate(),
            title,
            description,
            severity,
            cve_ids=cve_ids,
            cwe_ids=cwe_ids,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            original_severity=original_severity,
            demotion_reason=demotion_reason,
        )

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
        cve_ids: tuple[str, ...] = (),
        cwe_ids: tuple[str, ...] = (),
        cvss_score: float | None = None,
        cvss_vector: str | None = None,
        original_severity: Severity | None = None,
        demotion_reason: SeverityDemotionReason | None = None,
    ) -> Finding:
        """Rebuild a Finding from stored state (persistence boundary).

        Bypasses lifecycle transitions — the caller (mapper) is trusted to
        provide a consistent state. Structural invariants (non-empty title,
        timezone-aware timestamps) are still enforced.
        """
        ensure_non_empty(title, "Finding title")
        ensure_non_empty(description, "Finding description")
        ensure_timezone_aware(discovered_at, "discovered_at")
        _ensure_valid_cvss_score(cvss_score)

        f = cls.__new__(cls)
        f._id = finding_id
        f._title = title
        f._description = description
        f._severity = severity
        f._status = status
        f._discovered_at = discovered_at
        f._evidence = list(evidence) if evidence is not None else []
        f._recommendations = list(recommendations) if recommendations is not None else []
        f._cve_ids = tuple(cve_ids)
        f._cwe_ids = tuple(cwe_ids)
        f._cvss_score = cvss_score
        f._cvss_vector = cvss_vector
        f._original_severity = original_severity
        f._demotion_reason = demotion_reason
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

    @property
    def cve_ids(self) -> tuple[str, ...]:
        """CVE identifiers, if the scanner that produced this finding
        correlates to CVE data (Nuclei, Trivy). Empty when it doesn't
        (e.g. Nmap's raw port/service findings) - never fabricated."""
        return self._cve_ids

    @property
    def cwe_ids(self) -> tuple[str, ...]:
        return self._cwe_ids

    @property
    def cvss_score(self) -> float | None:
        return self._cvss_score

    @property
    def cvss_vector(self) -> str | None:
        return self._cvss_vector

    @property
    def original_severity(self) -> Severity | None:
        """The severity path/status-only classification would have assigned,
        before a scanner's content-based demotion heuristic reduced it.
        ``None`` means this finding was never demoted."""
        return self._original_severity

    @property
    def demotion_reason(self) -> SeverityDemotionReason | None:
        """Why ``severity`` is lower than ``original_severity`` - structured,
        not prose (Phase 2B-c Priority 1b). ``None`` means never demoted."""
        return self._demotion_reason

    @property
    def was_demoted(self) -> bool:
        return self._demotion_reason is not None

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
