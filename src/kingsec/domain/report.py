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
from datetime import UTC, datetime
from typing import Any

from .assessment import Assessment, ScannerRunSummary
from .enums import AssessmentStatus, FindingStatus, Severity
from .errors import IllegalStateTransition
from .evidence import Evidence, Recommendation

# Plain-language headlines keyed by the overall (highest actionable) severity.
_VERDICT_HEADLINES: dict[Severity, str] = {
    Severity.CRITICAL: "Critical security issues found — immediate action required.",
    Severity.HIGH: "High-risk issues found — prompt remediation recommended.",
    Severity.MEDIUM: "Moderate issues found — remediation recommended.",
    Severity.LOW: "Minor issues found — review advised.",
    Severity.INFORMATIONAL: "Informational observations only — no action required.",
}
_NO_ISSUES_HEADLINE = "No security issues identified."

# A deliberately simple, deterministic sizing heuristic keyed off severity —
# not an estimate of actual engineering hours, which no data source here can
# support. Stated as a heuristic in the report so it's never mistaken for a
# precise estimate (see FindingSummary.estimated_effort).
_EFFORT_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "Large",
    Severity.HIGH: "Large",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Small",
    Severity.INFORMATIONAL: "Small",
}

# Generic, curated remediation guidance for finding TYPES the current scanner
# integrations actually produce — used only as a fallback when no AI (or
# analyst) recommendation exists for a finding. Keyed by a distinctive title
# prefix, checked in order. This is real, well-known security guidance
# (independent of any specific CVE/CVSS), not a fabrication — it deliberately
# stays narrow: unmatched finding types get the honest "not available"
# fallback rather than a guessed recommendation. Extend this table as more
# finding-producing scanners are added (nuclei, nikto, etc.).
_GENERIC_REMEDIATION_BY_TITLE_PREFIX: tuple[tuple[str, str, str], ...] = (
    (
        "Open port ",
        "Review whether this open port/service is required",
        "If the service is not required, disable it or block the port at the "
        "host or network firewall. If it is required, restrict access to known "
        "source IPs/ranges, ensure the service is kept patched, and confirm it "
        "is configured per vendor hardening guidance rather than left at defaults.",
    ),
)


def generic_remediation_for(title: str, severity: Severity) -> Recommendation | None:
    """A generic recommendation for well-known finding types, or None.

    Priority mirrors the finding's own severity (the same convention used for
    AI-generated recommendations) rather than a fixed value.
    """
    for prefix, rec_title, rec_description in _GENERIC_REMEDIATION_BY_TITLE_PREFIX:
        if title.startswith(prefix):
            return Recommendation(title=rec_title, description=rec_description, priority=severity)
    return None


# Weighted deduction per severity, off a 100-point baseline. Shared by the
# report-list projection (infrastructure/persistence/repositories/report.py)
# and the PDF executive summary, so the two can never disagree.
_SCORE_PENALTY: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 0,
}


def compute_executive_score(severity_counts: tuple[tuple[Severity, int], ...]) -> float:
    """A single 0-100 score from a severity breakdown (100 = no weighted issues).

    Deducts a fixed penalty per finding at each severity, floored at 0. This is
    a deliberately simple, explainable heuristic — not a CVSS-style aggregate —
    so it can be stated in one sentence in the report.
    """
    penalty = sum(_SCORE_PENALTY[severity] * count for severity, count in severity_counts)
    return round(max(0.0, min(100.0, 100.0 - penalty)), 1)


@dataclass(frozen=True, slots=True)
class Verdict:
    """A plain-language conclusion derived from a set of findings."""

    highest_severity: Severity | None
    headline: str
    action_required: bool

    @classmethod
    def from_findings(cls, findings: tuple[Any, ...]) -> Verdict:
        """Derive the overall verdict, ignoring false positives."""
        actionable = [f for f in findings if f.status is not FindingStatus.FALSE_POSITIVE]
        if not actionable:
            return cls(None, _NO_ISSUES_HEADLINE, action_required=False)

        highest = max(f.severity for f in actionable)
        # Anything at LOW or above is worth acting on; informational is not.
        action_required = highest >= Severity.LOW
        return cls(highest, _VERDICT_HEADLINES[highest], action_required)


@dataclass(frozen=True, slots=True)
class FindingSummary:
    """An immutable snapshot of one finding, as it appears in a report.

    Carries the actual evidence and recommendation content (not just counts),
    so the report can render real technical detail and remediation text. CVE
    identifier, CVSS score/vector, and a specific affected-asset reference are
    deliberately NOT modeled here: the current scanning pipeline does not
    correlate a Finding to a CVE or a specific asset record, so there is no
    real data to carry — the report renders an honest "not available" for
    those facts rather than fabricating them.
    """

    finding_id: str
    title: str
    description: str
    severity: Severity
    status: FindingStatus
    evidence: tuple[Evidence, ...]
    recommendations: tuple[Recommendation, ...]
    # Populated by the GenerateReport use case (an application-layer concern,
    # never here — this dataclass stays a pure data snapshot with no AI-port
    # dependency). None means "not attempted or the AI call failed for this
    # finding"; the report renders an honest note in that case.
    ai_explanation: str | None = None

    @property
    def evidence_count(self) -> int:
        return len(self.evidence)

    @property
    def recommendation_count(self) -> int:
        return len(self.recommendations)

    @property
    def effective_recommendations(self) -> tuple[Recommendation, ...]:
        """Real (AI/analyst) recommendations if any exist, else a generic
        fallback for well-known finding types (see ``generic_remediation_for``).
        Never fabricates for finding types not in that curated table."""
        if self.recommendations:
            return self.recommendations
        generic = generic_remediation_for(self.title, self.severity)
        return (generic,) if generic else ()

    @property
    def estimated_effort(self) -> str:
        """A deterministic severity-based sizing heuristic (Large/Medium/Small).

        This is not a data-driven estimate — no real effort-tracking data
        exists anywhere upstream — so it's a stated heuristic, not a specific
        time/hours claim.
        """
        return _EFFORT_BY_SEVERITY[self.severity]


@dataclass(frozen=True, slots=True)
class HistoryPoint:
    """One prior report's score for the same target, for a trend chart."""

    generated_at: datetime
    executive_score: float


@dataclass(frozen=True, slots=True)
class Report:
    """An immutable, conclusions-first report for a completed assessment."""

    assessment_id: str
    target: str
    generated_at: datetime
    verdict: Verdict
    entries: tuple[FindingSummary, ...]  # ordered most-severe first
    severity_counts: tuple[tuple[Severity, int], ...]  # present severities, desc
    # Whether an AI provider was available when this report was generated
    # (set by GenerateReport, an application-layer concern — from_assessment
    # itself never touches AI). False means every entry's ai_explanation is
    # None because no provider was configured, not because calls failed.
    ai_enabled: bool = False
    # Prior reports for the same target, oldest first, visible to the same
    # requester (set by GenerateReport — respects the exact same ownership
    # boundary as everything else, never queried with elevated access).
    # Captured once at generation time (a report is a true, non-drifting
    # snapshot), not re-queried on every later download.
    history: tuple[HistoryPoint, ...] = ()
    # Authorization facts for the cover page (who authorized this assessment,
    # and what scope). A completed assessment is always authorized, so these
    # are non-empty in practice; the fallback only guards the type checker.
    authorized_by: str = ""
    scope: str = ""
    # Which scanners ran and why others were skipped - carried over from the
    # assessment as-is, so a reader never needs to return to the live app to
    # see it. Empty for assessments that predate this feature.
    scanner_summary: tuple[ScannerRunSummary, ...] = ()

    @classmethod
    def from_assessment(cls, assessment: Assessment, *, generated_at: datetime | None = None) -> Report:
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
                description=f.description,
                severity=f.severity,
                status=f.status,
                evidence=f.evidence,
                recommendations=f.recommendations,
            )
            for f in ordered
        )

        # Full, honest breakdown over ALL findings (present severities only).
        counts: dict[Severity, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        severity_counts = tuple(sorted(counts.items(), key=lambda kv: kv[0], reverse=True))

        authorization = assessment.authorization
        return cls(
            assessment_id=str(assessment.id),
            target=str(assessment.target),
            generated_at=generated_at or datetime.now(UTC),
            verdict=Verdict.from_findings(findings),
            entries=entries,
            severity_counts=severity_counts,
            authorized_by=authorization.authorized_by if authorization else "",
            scope=authorization.scope if authorization else "",
            scanner_summary=assessment.scanner_summary,
        )

    # --- convenience ---------------------------------------------------------
    @property
    def total_findings(self) -> int:
        return len(self.entries)

    @property
    def executive_score(self) -> float:
        """A single 0-100 aggregate score derived from the severity breakdown."""
        return compute_executive_score(self.severity_counts)

    def count_for(self, severity: Severity) -> int:
        """Number of findings at a given severity (0 if none)."""
        for level, count in self.severity_counts:
            if level is severity:
                return count
        return 0
