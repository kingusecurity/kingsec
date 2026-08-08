"""The Assessment aggregate root.

This is the heart of the domain. It owns the assessment lifecycle and is the
*only* way findings enter the model, so every rule about "when may this happen"
lives here in one place.

The authorization gate (KingSec's central trust rule) is enforced structurally:
RUNNING is reachable only from AUTHORIZED, and AUTHORIZED is reachable only via
``authorize()`` — which requires an ``Authorization`` value object. Therefore an
assessment that was never authorized can never run. This is defence in depth: it
holds even if some future caller forgets an infrastructure-level check.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from .authorization import Authorization
from .enums import AssessmentStatus, Severity
from .errors import IllegalStateTransition, InvariantViolation
from .finding import Finding
from .identifiers import AssessmentId, FindingId
from .target import Target

# Default sentinel for optional org/team/owner fields.
_UNSET = object()


@dataclass(frozen=True, slots=True)
class ScannerRunSummary:
    """A durable, post-scan record of one scanner's outcome.

    Captured once, at completion, from the (in-memory, ephemeral)
    execution-tracking state - this is what makes "which scanners ran and
    why others didn't" survive past the point where that tracking state
    is gone, without needing to return to the live app.
    """

    scanner_id: str
    name: str
    status: str  # "completed" | "failed" | "skipped" | ... (mirrors ScannerProgress.status)
    findings_count: int = 0
    skipped_reason: str | None = None

# Legal state transitions. An empty set marks a terminal state.
_ALLOWED_ASSESSMENT_TRANSITIONS: dict[AssessmentStatus, set[AssessmentStatus]] = {
    AssessmentStatus.DRAFT: {AssessmentStatus.AUTHORIZED, AssessmentStatus.CANCELLED},
    AssessmentStatus.AUTHORIZED: {AssessmentStatus.RUNNING, AssessmentStatus.CANCELLED},
    AssessmentStatus.RUNNING: {
        AssessmentStatus.COMPLETED,
        AssessmentStatus.FAILED,
        AssessmentStatus.CANCELLED,
    },
    AssessmentStatus.COMPLETED: set(),
    AssessmentStatus.CANCELLED: set(),
    AssessmentStatus.FAILED: set(),
}


class Assessment:
    """A security assessment of a single target."""

    def __init__(
        self,
        assessment_id: AssessmentId,
        target: Target,
        *,
        created_at: datetime | None = None,
        profile_id: str | None = None,
    ) -> None:
        if not isinstance(assessment_id, AssessmentId):
            raise InvariantViolation("assessment_id must be an AssessmentId")
        if not isinstance(target, Target):
            raise InvariantViolation("target must be a Target")

        moment = created_at or datetime.now(UTC)

        self._id = assessment_id
        self._target = target
        self._created_at = moment
        self._status = AssessmentStatus.DRAFT
        self._authorization: Authorization | None = None
        self._failure_reason: str | None = None
        self._organization_id: str | None = None
        self._team_id: str | None = None
        self._owner_id: str | None = None
        # Which AssessmentProfile this scan was planned against, if any.
        # None means "no profile" - the execution layer runs every
        # target-compatible scanner, exactly as it always has.
        self._profile_id = profile_id
        # Populated once, at completion, from the execution engine's
        # per-scanner state - empty until then, and permanently empty for
        # assessments that predate this feature.
        self._scanner_summary: tuple[ScannerRunSummary, ...] = ()
        # Keyed by FindingId to make duplicate detection O(1) and cheap.
        self._findings: dict[FindingId, Finding] = {}

    # --- factory -------------------------------------------------------------
    @classmethod
    def create(
        cls, target: Target, *, created_at: datetime | None = None, profile_id: str | None = None
    ) -> Assessment:
        """Create a new DRAFT assessment with a freshly generated id."""
        return cls(AssessmentId.generate(), target, created_at=created_at, profile_id=profile_id)

    @classmethod
    def reconstitute(
        cls,
        *,
        assessment_id: AssessmentId,
        target: Target,
        status: AssessmentStatus,
        created_at: datetime,
        authorization: Authorization | None,
        failure_reason: str | None = None,
        findings: list[Finding] | None = None,
        profile_id: str | None = None,
        scanner_summary: tuple[ScannerRunSummary, ...] = (),
    ) -> Assessment:
        """Rebuild an Assessment from stored state (persistence boundary).

        Bypasses lifecycle transitions — the caller (mapper) is trusted to
        provide a consistent state. Structural invariants (valid id, target type)
        are still enforced.
        """
        a = cls.__new__(cls)
        a._id = assessment_id
        a._target = target
        a._created_at = created_at
        a._status = status
        a._authorization = authorization
        a._failure_reason = failure_reason
        a._organization_id = None
        a._team_id = None
        a._owner_id = None
        a._profile_id = profile_id
        a._scanner_summary = scanner_summary
        a._findings = {f.id: f for f in (findings or [])}
        if len(a._findings) != len(findings or []):
            raise InvariantViolation("duplicate finding id in reconstitution")
        return a

    def set_ownership(self, owner_id: str, organization_id: str | None = None, team_id: str | None = None) -> None:
        self._owner_id = owner_id
        self._organization_id = organization_id
        self._team_id = team_id

    # --- read-only accessors -------------------------------------------------
    @property
    def id(self) -> AssessmentId:
        return self._id

    @property
    def organization_id(self) -> str | None:
        return self._organization_id

    @property
    def team_id(self) -> str | None:
        return self._team_id

    @property
    def owner_id(self) -> str | None:
        return self._owner_id

    @property
    def target(self) -> Target:
        return self._target

    @property
    def status(self) -> AssessmentStatus:
        return self._status

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def authorization(self) -> Authorization | None:
        return self._authorization

    @property
    def is_authorized(self) -> bool:
        return self._authorization is not None

    @property
    def failure_reason(self) -> str | None:
        return self._failure_reason

    @property
    def profile_id(self) -> str | None:
        return self._profile_id

    @property
    def scanner_summary(self) -> tuple[ScannerRunSummary, ...]:
        return self._scanner_summary

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(self._findings.values())

    @property
    def highest_severity(self) -> Severity | None:
        """The most severe finding's severity, or None if there are no findings."""
        if not self._findings:
            return None
        return max(finding.severity for finding in self._findings.values())

    # --- lifecycle -----------------------------------------------------------
    def authorize(self, authorization: Authorization) -> None:
        """Record authorization and move DRAFT -> AUTHORIZED."""
        if not isinstance(authorization, Authorization):
            raise InvariantViolation("authorization must be an Authorization")
        self._transition_to(AssessmentStatus.AUTHORIZED)
        self._authorization = authorization

    def start(self) -> None:
        """Begin active work: AUTHORIZED -> RUNNING (the authorization gate)."""
        # Explicit, friendly message for the single most important rule.
        if self._status is not AssessmentStatus.AUTHORIZED:
            raise IllegalStateTransition(
                "an assessment must be authorized before it can start",
                current=self._status,
                attempted=AssessmentStatus.RUNNING,
            )
        # Belt-and-suspenders: AUTHORIZED implies an Authorization is present.
        if self._authorization is None:  # pragma: no cover - unreachable safeguard
            raise InvariantViolation("authorized assessment has no authorization record")
        self._transition_to(AssessmentStatus.RUNNING)

    def record_finding(self, finding: Finding) -> None:
        """Add a finding. Only permitted while RUNNING; ids must be unique."""
        if not isinstance(finding, Finding):
            raise InvariantViolation("finding must be a Finding")
        if self._status is not AssessmentStatus.RUNNING:
            raise IllegalStateTransition(
                f"cannot record findings while assessment is {self._status.value}",
                current=self._status,
            )
        if finding.id in self._findings:
            raise InvariantViolation(f"duplicate finding id {finding.id.value!r}")
        self._findings[finding.id] = finding

    def record_scanner_summary(self, summary: tuple[ScannerRunSummary, ...]) -> None:
        """Attach the final per-scanner outcome record. Call once, right
        before ``complete()`` - same lifecycle window as ``record_finding``,
        since both are facts about a scan that's still RUNNING."""
        if self._status is not AssessmentStatus.RUNNING:
            raise IllegalStateTransition(
                f"cannot record scanner summary while assessment is {self._status.value}",
                current=self._status,
            )
        self._scanner_summary = summary

    def complete(self) -> None:
        """Finish successfully: RUNNING -> COMPLETED."""
        self._transition_to(AssessmentStatus.COMPLETED)

    def fail(self, reason: str) -> None:
        """Abort due to error: RUNNING -> FAILED, recording why."""
        ensure_reason = reason.strip() if isinstance(reason, str) else ""
        if not ensure_reason:
            raise InvariantViolation("a failure reason is required")
        self._transition_to(AssessmentStatus.FAILED)
        self._failure_reason = reason

    def cancel(self) -> None:
        """Cancel a not-yet-terminal assessment."""
        self._transition_to(AssessmentStatus.CANCELLED)

    # --- internals -----------------------------------------------------------
    def _transition_to(self, new_status: AssessmentStatus) -> None:
        allowed = _ALLOWED_ASSESSMENT_TRANSITIONS[self._status]
        if new_status not in allowed:
            raise IllegalStateTransition(
                f"cannot move assessment from {self._status.value} to {new_status.value}",
                current=self._status,
                attempted=new_status,
            )
        self._status = new_status

    # --- identity ------------------------------------------------------------
    def __eq__(self, other: object) -> bool:
        return isinstance(other, Assessment) and other._id == self._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return f"Assessment(id={self._id.value!r}, status={self._status.value}, findings={len(self._findings)})"
