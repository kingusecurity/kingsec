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
from .enums import AssessmentStatus, FindingStatus, Severity, SeverityDemotionReason
from .errors import IllegalStateTransition
from .evidence import Evidence, Recommendation

# Plain-language headlines keyed by the overall (highest actionable) severity.
# Used only when scanner coverage was complete.
_VERDICT_HEADLINES: dict[Severity, str] = {
    Severity.CRITICAL: "Critical security issues found — immediate action required.",
    Severity.HIGH: "High-risk issues found — prompt remediation recommended.",
    Severity.MEDIUM: "Moderate issues found — remediation recommended.",
    Severity.LOW: "Minor issues found — review advised.",
    Severity.INFORMATIONAL: "Informational observations only — no action required.",
}
_NO_ISSUES_HEADLINE = "No security issues identified."

# Phase 2A-b: when coverage is incomplete, the headline must LEAD with that
# fact, never a reassuring findings clause (the Run #4 defect reproduced on
# the report's own score/gauge page, behind a caveat most readers never
# reach). "Among the scanners that completed" versions of the severity
# clauses replace the old, ordering-agnostic _VERDICT_HEADLINES text for
# this case - deliberately worded to never sound like a clean-bill verdict.
_SEVERITY_AMONG_COMPLETED: dict[Severity, str] = {
    Severity.CRITICAL: "Among the scanners that completed, Critical severity issues were found.",
    Severity.HIGH: "Among the scanners that completed, High-risk issues were found.",
    Severity.MEDIUM: "Among the scanners that completed, Moderate issues were found.",
    Severity.LOW: "Among the scanners that completed, minor (Low-severity) issues were found.",
    Severity.INFORMATIONAL: "Among the scanners that completed, only informational-level observations were found.",
}
_NO_ACTIONABLE_AMONG_COMPLETED = "No actionable findings were recorded among the scanners that completed."


def failed_scanners_in(scanner_summary: tuple[ScannerRunSummary, ...]) -> tuple[ScannerRunSummary, ...]:
    """Scanners that did not reach SUCCEEDED — the only category that
    makes coverage incomplete.

    Phase 2A FIX 3/6 (superseding the Phase 10 version of this function):
    every scanner in ``scanner_summary`` now has a real, terminal
    ``ScannerRunState`` — there is no longer a category of scanner that
    is silently absent from this tuple because it was "never applicable"
    (Phase 2A Correction 2b made the planner decide every scanner in the
    profile, always). So "incomplete coverage" is now simply: did every
    scanner that was scheduled for this assessment SUCCEED? A scanner
    that was skipped as genuinely inapplicable (SKIPPED_INCOMPATIBLE) is
    still, honestly, a scanner whose coverage this assessment does not
    have — the Run #4 reference case is exactly this: 6 scanners the
    operator would reasonably expect to run, that didn't, none of them
    literally "failed" in the old narrow sense. Undercounting this is
    the false-assurance defect this phase exists to close.
    """
    return tuple(s for s in scanner_summary if not s.status.is_success)


def _coverage_lead(failed: tuple[ScannerRunSummary, ...], total_attempted: int) -> str:
    """The LEADING statement of an incomplete-coverage verdict headline.

    Phase 2A-b: this must be the first thing the headline says, never
    appended after a findings-severity clause — a reader who never gets
    past the first sentence must not be able to read this as a clean
    result. Only scanner display names (``ScannerRunSummary.name``) and
    counts are interpolated - both are on Phase 08 §2's explicit safe
    list. Never a path, binary location, command line, internal hostname,
    or raw ``str(exc)`` - none of that is available on
    ``ScannerRunSummary`` at all, so there is nothing unsafe here to
    accidentally include.
    """
    succeeded = total_attempted - len(failed)
    names = ", ".join(s.name for s in failed)
    return (
        f"Incomplete assessment — {succeeded} of {total_attempted} scanners ran; "
        f"findings are partial. {len(failed)} scanner(s) did not complete ({names}) — "
        "see Scanner Coverage for details."
    )

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
    def from_findings(
        cls,
        findings: tuple[Any, ...],
        scanner_summary: tuple[ScannerRunSummary, ...] = (),
    ) -> Verdict:
        """Derive the overall verdict, ignoring false positives.

        Phase 10: ``scanner_summary`` is consulted only to detect
        incomplete coverage (see ``failed_scanners_in``) - it never changes
        ``highest_severity``, which stays driven purely by findings. A
        partially-executed assessment must not present as an unqualified
        clean result: incomplete coverage always forces
        ``action_required=True`` and qualifies the headline, even when the
        severity-only verdict would otherwise have been the generic "no
        action required" text (Phase 09 §5 Scenario 3's exact live defect).
        """
        failed = failed_scanners_in(scanner_summary)
        incomplete = bool(failed)

        actionable = [f for f in findings if f.status is not FindingStatus.FALSE_POSITIVE]
        if not actionable:
            if incomplete:
                # Phase 2A-b: coverage leads; the "nothing actionable" note
                # is a subordinate clause, never the opening claim.
                headline = f"{_coverage_lead(failed, len(scanner_summary))} {_NO_ACTIONABLE_AMONG_COMPLETED}"
                return cls(None, headline, action_required=True)
            return cls(None, _NO_ISSUES_HEADLINE, action_required=False)

        highest = max(f.severity for f in actionable)
        # Anything at LOW or above is worth acting on; informational is not
        # -- unless coverage is incomplete, in which case following up on
        # the scanners that didn't run is itself the required action.
        action_required = highest >= Severity.LOW or incomplete
        if incomplete:
            # Phase 2A-b: coverage leads, severity is a subordinate clause -
            # never the reverse. The old ordering put "Minor issues found —
            # review advised." first and the coverage gap second, which a
            # reader could stop after the first sentence and walk away
            # reassured; this is the exact defect this phase exists to fix.
            headline = f"{_coverage_lead(failed, len(scanner_summary))} {_SEVERITY_AMONG_COMPLETED[highest]}"
        else:
            headline = _VERDICT_HEADLINES[highest]
        return cls(highest, headline, action_required)


@dataclass(frozen=True, slots=True)
class FindingSummary:
    """An immutable snapshot of one finding, as it appears in a report.

    Carries the actual evidence and recommendation content (not just counts),
    so the report can render real technical detail and remediation text.

    CVE/CWE identifiers and CVSS score/vector are populated when the scanner
    that produced the underlying Finding genuinely correlates to that data
    (Nuclei's template classification, Trivy's vulnerability database) - they
    are empty/None otherwise (e.g. Nmap's raw port/service findings, which
    carry no CVE data at all), never fabricated or guessed. A specific
    affected-asset reference is still not modeled: the current pipeline has
    no per-asset record to point to, only the assessment's single target.
    """

    finding_id: str
    title: str
    description: str
    severity: Severity
    status: FindingStatus
    evidence: tuple[Evidence, ...]
    recommendations: tuple[Recommendation, ...]
    cve_ids: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    cvss_score: float | None = None
    cvss_vector: str | None = None
    # Populated by the GenerateReport use case (an application-layer concern,
    # never here — this dataclass stays a pure data snapshot with no AI-port
    # dependency). None means "not attempted or the AI call failed for this
    # finding"; the report renders an honest note in that case.
    ai_explanation: str | None = None
    # Phase 2B-c Priority 1b: carried straight from the source Finding -
    # both None unless a scanner's content-based heuristic demoted this
    # finding's severity below what path/status-only scoring would have
    # assigned. Structured, so the report can disclose demotions honestly
    # (see _severity_demotion_note in templates.py) rather than silently
    # changing the answer.
    original_severity: Severity | None = None
    demotion_reason: SeverityDemotionReason | None = None

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
    # Phase 2A FIX 3/4: the assessment's actual terminal status
    # (COMPLETED or COMPLETED_WITH_GAPS) at the moment this report was
    # generated - the report must say which one it was, not silently
    # assume "Completed" the way it safely could before COMPLETED_WITH_GAPS
    # existed. Defaults to COMPLETED only for pre-existing callers/fixtures
    # that never set it explicitly.
    assessment_status: AssessmentStatus = AssessmentStatus.COMPLETED

    @classmethod
    def from_assessment(cls, assessment: Assessment, *, generated_at: datetime | None = None) -> Report:
        """Build a report from a COMPLETED or COMPLETED_WITH_GAPS assessment.

        Phase 2A FIX 5: a FAILED assessment (zero scanners succeeded) is
        deliberately excluded here — there is no real data to report on,
        and generating a normal, scored report over an empty result set
        would itself be the false-assurance problem this phase exists to
        close. The caller gets a specific, honest reason why, not a
        generic state-transition error.
        """
        if assessment.status not in (AssessmentStatus.COMPLETED, AssessmentStatus.COMPLETED_WITH_GAPS):
            if assessment.status is AssessmentStatus.FAILED:
                raise IllegalStateTransition(
                    "no report can be generated: every scanner failed to complete for this "
                    "assessment, so no assessment data was collected",
                    current=assessment.status,
                )
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
                cve_ids=f.cve_ids,
                cwe_ids=f.cwe_ids,
                cvss_score=f.cvss_score,
                cvss_vector=f.cvss_vector,
                original_severity=f.original_severity,
                demotion_reason=f.demotion_reason,
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
            verdict=Verdict.from_findings(findings, assessment.scanner_summary),
            entries=entries,
            severity_counts=severity_counts,
            authorized_by=authorization.authorized_by if authorization else "",
            scope=authorization.scope if authorization else "",
            scanner_summary=assessment.scanner_summary,
            assessment_status=assessment.status,
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
