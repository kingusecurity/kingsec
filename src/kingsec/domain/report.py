"""The Report — an immutable, conclusions-first snapshot of a completed assessment.

Design choices reflecting KingSec's philosophy:
    * Conclusions first: the report leads with a plain-language ``Verdict`` and
      orders findings worst-first, so the reader sees the bottom line immediately.
    * Honesty: severity counts cover *all* findings (nothing hidden), while the
      verdict is derived from actionable findings (false positives excluded).
    * True snapshot: findings are captured into immutable ``FindingSummary`` value
      objects, so the report cannot drift even if the underlying entities change.

A report may only be generated from a COMPLETED assessment — you cannot conclude
on work that isn't finished.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .assessment import Assessment
from .enums import AssessmentStatus, FindingStatus, Severity
from .errors import IllegalStateTransition

# Plain-language headlines keyed by the overall (highest actionable) severity.
_VERDICT_HEADLINES: dict[Severity, str] = {
    Severity.CRITICAL: "Critical security issues found — immediate action required.",
    Severity.HIGH: "High-risk issues found — prompt remediation recommended.",
    Severity.MEDIUM: "Moderate issues found — remediation recommended.",
    Severity.LOW: "Minor issues found — review advised.",
    Severity.INFORMATIONAL: "Informational observations only — no action required.",
}
_NO_ISSUES_HEADLINE = "No security issues identified."


@dataclass(frozen=True, slots=True)
class Verdict:
    """A plain-language conclusion derived from a set of findings."""

    highest_severity: Severity | None
    headline: str
    action_required: bool

    @classmethod
    def from_findings(cls, findings: tuple) -> "Verdict":
        """Derive the overall verdict, ignoring false positives."""

        actionable = [
            f for f in findings if f.status is not FindingStatus.FALSE_POSITIVE
        ]
        if not actionable:
            return cls(None, _NO_ISSUES_HEADLINE, action_required=False)

        highest = max(f.severity for f in actionable)
        # Anything at LOW or above is worth acting on; informational is not.
        action_required = highest >= Severity.LOW
        return cls(highest, _VERDICT_HEADLINES[highest], action_required)


@dataclass(frozen=True, slots=True)
class FindingSummary:
    """An immutable snapshot of one finding, as it appears in a report."""

    finding_id: str
    title: str
    severity: Severity
    status: FindingStatus
    evidence_count: int
    recommendation_count: int


@dataclass(frozen=True, slots=True)
class Report:
    """An immutable, conclusions-first report for a completed assessment."""

    assessment_id: str
    target: str
    generated_at: datetime
    verdict: Verdict
    entries: tuple[FindingSummary, ...]           # ordered most-severe first
    severity_counts: tuple[tuple[Severity, int], ...]  # present severities, desc

    @classmethod
    def from_assessment(
        cls, assessment: Assessment, *, generated_at: datetime | None = None
    ) -> "Report":
        """Build a report from a COMPLETED assessment (else raise)."""

        if assessment.status is not AssessmentStatus.COMPLETED:
            raise IllegalStateTransition(
                "a report can only be generated from a completed assessment",
                current=assessment.status,
            )

        findings = assessment.findings

        # Snapshot each finding into an immutable summary, worst severity first.
        ordered = sorted(findings, key=lambda f: f.severity, reverse=True)
        entries = tuple(
            FindingSummary(
                finding_id=str(f.id),
                title=f.title,
                severity=f.severity,
                status=f.status,
                evidence_count=len(f.evidence),
                recommendation_count=len(f.recommendations),
            )
            for f in ordered
        )

        # Full, honest breakdown over ALL findings (present severities only).
        counts: dict[Severity, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        severity_counts = tuple(
            sorted(counts.items(), key=lambda kv: kv[0], reverse=True)
        )

        return cls(
            assessment_id=str(assessment.id),
            target=str(assessment.target),
            generated_at=generated_at or datetime.now(timezone.utc),
            verdict=Verdict.from_findings(findings),
            entries=entries,
            severity_counts=severity_counts,
        )

    # --- convenience ---------------------------------------------------------
    @property
    def total_findings(self) -> int:
        return len(self.entries)

    def count_for(self, severity: Severity) -> int:
        """Number of findings at a given severity (0 if none)."""

        for level, count in self.severity_counts:
            if level is severity:
                return count
        return 0
