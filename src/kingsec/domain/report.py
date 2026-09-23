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

import logging
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .assessment import Assessment, ScannerRunSummary
from .enums import AssessmentStatus, FindingStatus, Severity, SeverityDemotionReason
from .errors import IllegalStateTransition
from .evidence import Evidence, Recommendation

# Stdlib logging only - permitted in domain per docs/FOUNDATION.md §8
# ("domain imports only the standard library and shared"). Used solely to
# record when a persisted assessment_status disagrees with what its own
# scanner_summary implies (see from_assessment() below) - never for control
# flow, and no infrastructure/adapter dependency is introduced.
_logger = logging.getLogger(__name__)

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

# Phase 2C Step 2, FIX 2: a severity-based "estimated fix effort" heuristic
# (_EFFORT_BY_SEVERITY, FindingSummary.estimated_effort) used to live here.
# Removed - real report evidence showed it rendering "Large" for changing a
# default password (a Critical-severity but trivial-to-fix finding), because
# severity measures IMPACT, not engineering effort, and no real
# effort-tracking data exists anywhere upstream to ground an estimate in
# instead. A fabricated estimate on a customer deliverable is worse than no
# estimate - do not reintroduce a differently-shaped guess (e.g. by finding
# type or CWE) without a real data source behind it.

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

# Phase 2C Step 2, FIX 1: real DVWA report evidence showed the single
# Critical finding (a nuclei dvwa-default-login match, CWE-798) rendering
# "No specific remediation guidance is available for this finding" - the
# most important finding in the report was the least actionable, because
# nuclei templates routinely carry no info.remediation text and the title-
# prefix table above only ever covered Nmap's "Open port " findings.
#
# Keyed by CWE id (normalized upper-case for lookup - Nuclei's own
# classification.cwe-id has been observed both upper- and lower-case in
# real captured output, e.g. "cwe-693" for http-missing-security-headers).
# Covers, at minimum, every CWE actually observed in this project's E2E
# evidence: CWE-798 (hard-coded credentials), CWE-200 (sensitive
# information exposure), CWE-614 (cookie missing Secure), CWE-1004
# (cookie missing HttpOnly), CWE-693 (protection mechanism failure - the
# CWE nuclei's own http-missing-security-headers.yaml template declares).
# Real, well-known, CWE-class guidance - same standard as the title-prefix
# table above, not a fabrication.
_GENERIC_REMEDIATION_BY_CWE: dict[str, tuple[str, str]] = {
    "CWE-798": (
        "Remove hard-coded or default credentials",
        "Change any default or hard-coded credentials immediately, generate "
        "unique credentials per deployment at install time, enforce a strong "
        "password policy, and rotate any credentials that may have been exposed.",
    ),
    "CWE-200": (
        "Restrict exposure of sensitive information",
        "Review what this response or endpoint discloses and restrict it to "
        "authorized users only. Remove sensitive data from responses, logs, and "
        "error messages where it is not required, and apply access controls "
        "where disclosure is needed for legitimate functionality.",
    ),
    "CWE-614": (
        "Set the Secure attribute on sensitive cookies",
        "Mark cookies that carry session or sensitive data with the Secure "
        "attribute (and HttpOnly/SameSite as appropriate) so they are never "
        "sent over an unencrypted connection, and serve the application "
        "exclusively over HTTPS.",
    ),
    "CWE-1004": (
        "Set the HttpOnly attribute on sensitive cookies",
        "Mark cookies that carry session or sensitive data with the HttpOnly "
        "attribute so they cannot be read or modified by client-side script, "
        "mitigating session theft via cross-site scripting.",
    ),
    "CWE-693": (
        "Configure the missing protection mechanism",
        "Configure the specific missing HTTP security header(s) or protection "
        "mechanism identified in this finding's description at the web server "
        "or application layer, following current browser/platform security "
        "best practices appropriate to this application's risk profile.",
    ),
}

# Phase 2C Step 2, FIX 1's unconditional requirement: "Never render 'no
# guidance available' for a Critical or High finding" - stronger than "cover
# more CWEs", since a Critical/High finding with no CWE at all, or a CWE not
# yet in the table above, must still never render silence. This is
# deliberately NOT a technical fix (it cannot honestly claim one for a
# finding type it doesn't recognize) - it says so plainly and directs the
# reader to get human judgment, which is a true and useful thing to say
# about a serious finding this table doesn't yet cover.
_SEVERITY_FALLBACK_REMEDIATION: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: (
        "Investigate and remediate immediately",
        "No specific automated remediation guidance is available for this "
        "finding type. Given its Critical severity, treat it as urgent: engage "
        "a security analyst to confirm exploitability and determine the "
        "appropriate fix before deprioritizing this finding.",
    ),
    Severity.HIGH: (
        "Investigate and remediate promptly",
        "No specific automated remediation guidance is available for this "
        "finding type. Given its High severity, have a security analyst assess "
        "exploitability and determine the appropriate fix promptly.",
    ),
}


def generic_remediation_for(
    title: str, severity: Severity, cwe_ids: tuple[str, ...] = ()
) -> Recommendation | None:
    """A generic recommendation for well-known finding types, or None.

    Checked in order: (1) title-prefix match against a curated table of
    finding TYPES this project's scanners actually produce, (2) CWE-class
    match against a curated table of well-known CWE remediation, (3) for
    Critical/High severity only, an honest "no specific guidance, get human
    judgment" fallback - see _SEVERITY_FALLBACK_REMEDIATION's own docstring
    for why that one is deliberately not a technical fix. Below Critical/
    High, an unmatched finding type still returns None rather than
    fabricating guidance.

    Priority mirrors the finding's own severity (the same convention used for
    AI-generated recommendations) rather than a fixed value.
    """
    for prefix, rec_title, rec_description in _GENERIC_REMEDIATION_BY_TITLE_PREFIX:
        if title.startswith(prefix):
            return Recommendation(title=rec_title, description=rec_description, priority=severity)
    for cwe in cwe_ids:
        cwe_match = _GENERIC_REMEDIATION_BY_CWE.get(cwe.upper())
        if cwe_match:
            rec_title, rec_description = cwe_match
            return Recommendation(title=rec_title, description=rec_description, priority=severity)
    severity_fallback = _SEVERITY_FALLBACK_REMEDIATION.get(severity)
    if severity_fallback:
        rec_title, rec_description = severity_fallback
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


def compute_executive_score_v1(severity_counts: tuple[tuple[Severity, int], ...]) -> float:
    """DEPRECATED (Phase 2C Step 2) — the original linear-deduction formula.

    Kept only to reproduce historical reports persisted with
    score_version="v1" exactly, forever. Never call this for new report
    generation — use compute_executive_score() (v2) below.

    Defect this formula had (why it was replaced): unbounded linear
    deduction saturates to 0 on realistic finding counts (4 Criticals, or
    ~50 Lows, both single-target-realistic), and once saturated a customer
    who remediates ten findings and re-runs still sees 0 — removing any
    visible reason to buy a reassessment. See docs/E2E-EVIDENCE-PHASE2B.md
    and the Phase 2C Step 1 calibration report for the real-data evidence.
    """
    penalty = sum(_SCORE_PENALTY[severity] * count for severity, count in severity_counts)
    return round(max(0.0, min(100.0, 100.0 - penalty)), 1)


# Retention constants: PROVISIONAL. Read before changing.
#
# CRITICAL (0.72) and HIGH (0.88) are NOT calibrated against real data.
# Evidence set to date: one observed Critical (a nuclei dvwa-default-login
# match against DVWA — a deliberately engineered test-fixture weakness,
# genuine but not organically discovered) and ZERO observed Highs. The only
# High counts on record came from the ffuf flood defect and are discarded
# noise. Both constants were chosen for mathematical properties (bounded,
# strictly monotonic, explainable as "X% of remaining score retained per
# finding"), not from observation.
#
# MEDIUM (0.95) and LOW (0.985) rest on more observations than the above but
# are also uncalibrated: effectively one target's worth of data (Run 1's 5
# Medium / 5 Low; Run 2 contributed none after host-service exclusion).
#
# CALIBRATE WHEN: at least 10 organically-discovered Critical or High
# findings exist across 5+ distinct production-representative targets. Until
# then these are placeholders and the score is a relative indicator, not a
# measurement.
#
# UNDERFLOW: strict monotonicity holds mathematically at any finding count,
# but stops being visible on screen well before it stops being true. For an
# all-LOW distribution, computed directly from these constants: two
# consecutive counts first round to the identical displayed value at
# N=190 (both show 5.7), and the hard floor — the score rounds to 0.0, a
# reassessment shows no improvement at all — is reached at N=503. The
# reassessment-improvement property this formula exists to provide only
# holds below that floor; do not claim it above. Per-severity hard floors
# (single-severity distribution, score first rounds to 0.0 at this count):
# CRITICAL=24, HIGH=60, MEDIUM=149, LOW=503.
#
# CRITICAL=24 IS THE ONE THAT MATTERS COMMERCIALLY, not just mathematically.
# Twenty-four Criticals is a realistic count for a genuinely compromised
# environment (not a flood-defect artifact the way thousands of Lows are) -
# beyond it, this score can no longer tell an SME "very bad" apart from
# "catastrophic"; both render as 0.0/Critical-band. An SME target will
# likely never reach this. An enterprise pilot, scanning a larger or
# already-compromised estate, might - better documented here than
# discovered in front of one.
#
# Full account: docs/E2E-EVIDENCE-PHASE2B.md
_SCORE_RETENTION: dict[Severity, float] = {
    Severity.CRITICAL: 0.72,
    Severity.HIGH: 0.88,
    Severity.MEDIUM: 0.95,
    Severity.LOW: 0.985,
    Severity.INFORMATIONAL: 1.00,
}


def compute_executive_score(severity_counts: tuple[tuple[Severity, int], ...]) -> float:
    """A single 0-100 score from a severity breakdown (100 = no weighted issues).

    v2 (Phase 2C Step 2): a bounded, strictly-monotonic multiplicative
    retention model — replaces the old linear-deduction formula
    (compute_executive_score_v1 above), which saturated to 0 on realistic
    finding counts and could never show a customer that remediation
    improved their score. Computed in log-space for numerical stability on
    large finding counts. See _SCORE_RETENTION's own docstring above for
    which constants are calibrated against real data and which aren't.

    This is a proprietary, explainable heuristic — it is explicitly NOT
    CVSS, CIS, or NIST-derived, borrows no vocabulary or methodology from
    those standards, and must not be presented as equivalent to or scored
    against them.
    """
    log_sum = sum(
        count * math.log(_SCORE_RETENTION[severity])
        for severity, count in severity_counts
        if _SCORE_RETENTION[severity] > 0
    )
    score = 100.0 * math.exp(log_sum)
    return round(max(0.0, min(100.0, score)), 1)


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
        fallback: by finding-type title, then by CWE class, then (Critical/
        High only) an honest "get human judgment" note - see
        ``generic_remediation_for``'s own docstring for the exact order.
        Below Critical/High, never fabricates for finding types not in the
        curated tables."""
        if self.recommendations:
            return self.recommendations
        generic = generic_remediation_for(self.title, self.severity, self.cwe_ids)
        return (generic,) if generic else ()


@dataclass(frozen=True, slots=True)
class HistoryPoint:
    """One prior report's score for the same target, for a trend chart.

    Phase 2C Step 2, Addition B: carries score_version because a score is
    meaningless without knowing which formula produced it (the same reason
    Report itself carries score_version) - a trend chart plotting v1 and
    v2 points as if directly comparable would show apparent improvement or
    decline that is really just a formula change. Defaults to "v2" (the
    current formula) purely to match Report's own default; every real
    construction site (GenerateReport._with_history, mappers.report_to_domain,
    templates._risk_over_time_chart) sets it explicitly rather than relying
    on this default.
    """

    generated_at: datetime
    executive_score: float
    score_version: str = "v2"


def derive_assessment_status(assessment: Assessment) -> AssessmentStatus:
    """The real completion state, computed live from ``assessment.scanner_summary``
    — the same ground truth ``submit_assessment.py``'s own orchestrator computes
    from when it first decides an assessment's terminal status — never trusted
    from ``assessment.status`` alone.

    Phase 2C Step 2 GAP-1 fix: this is the ONE place that determines the
    status a report actually reflects; nothing downstream of it re-derives
    or second-guesses this value on its own. Zero successes with at least
    one scheduled scanner means FAILED, regardless of what
    ``assessment.status`` says. Some-but-not-all successes means
    COMPLETED_WITH_GAPS. All succeeded means COMPLETED.

    Public (not ``_``-prefixed): ``Report.from_assessment()`` below calls it
    at generation time, and the report-download/metadata routes
    (adapters/inbound/web/routes.py) call it again at READ time - a stored
    report generated before this function existed can still be sitting in
    the database with a stale ``assessment_status``, and serving it from
    cache without re-checking would silently resurface the exact false
    claim generation-time now refuses to produce. Both call sites must stay
    on this one implementation, never grow their own copy.

    Falls back to ``assessment.status`` only when there is no scanner_summary
    at all to derive from (a pre-scanner-summary-feature assessment, or a test
    fixture that never calls ``record_scanner_summary()``) — there is nothing
    to derive in that case, so the persisted value is the only signal that
    exists.
    """
    scanner_summary = assessment.scanner_summary
    total_count = len(scanner_summary)
    if total_count == 0:
        return assessment.status
    succeeded_count = sum(1 for s in scanner_summary if s.status.is_success)
    if succeeded_count == 0:
        return AssessmentStatus.FAILED
    if succeeded_count < total_count:
        return AssessmentStatus.COMPLETED_WITH_GAPS
    return AssessmentStatus.COMPLETED


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
    # Phase 2C Step 2: which executive_score formula this report was
    # actually scored under. A report is an immutable snapshot - a report
    # persisted with score_version="v1" must keep reporting its v1 score
    # forever, never be silently rescored under a later formula on read.
    # Defaults to "v2" (the current formula) for every new report; existing
    # persisted rows are backfilled to "v1" by the Alembic migration that
    # introduced this field.
    score_version: str = "v2"
    # Phase 6 Task 5: which assessment profile was configured, if any -
    # carried straight from Assessment.profile_id (a real, pre-existing
    # property that from_assessment() simply never copied over before).
    # The Methodology section needs this to state what the operator
    # actually configured; None means no profile was selected (an
    # unscoped/ad-hoc assessment), not "not recorded" - Assessment itself
    # already distinguishes those two states via the same None value.
    profile_id: str | None = None

    @classmethod
    def from_assessment(cls, assessment: Assessment, *, generated_at: datetime | None = None) -> Report:
        """Build a report from a COMPLETED or COMPLETED_WITH_GAPS assessment.

        Phase 2A FIX 5: a FAILED assessment (zero scanners succeeded) is
        deliberately excluded here — there is no real data to report on,
        and generating a normal, scored report over an empty result set
        would itself be the false-assurance problem this phase exists to
        close. The caller gets a specific, honest reason why, not a
        generic state-transition error.

        Phase 2C Step 2 GAP-1 fix: that guarantee is checked against
        ``derive_assessment_status(assessment)`` — computed live from
        ``assessment.scanner_summary`` — never against ``assessment.status``
        directly. A persisted status CAN disagree with the scanner results
        it's supposed to summarize (concretely: assessments created before
        Phase 2A's status-determination logic existed and never backfilled;
        in principle, any future write path that fails to keep them in
        sync). When they disagree, the derived value wins and is what this
        report actually carries as ``assessment_status`` — the disagreement
        itself is logged with both values, never silently accepted.
        """
        derived_status = derive_assessment_status(assessment)
        if derived_status is not assessment.status:
            _logger.warning(
                "assessment %s status disagrees with its own scanner_summary "
                "(persisted=%s, derived=%s) - using the derived value",
                assessment.id,
                assessment.status.value,
                derived_status.value,
            )

        if derived_status not in (AssessmentStatus.COMPLETED, AssessmentStatus.COMPLETED_WITH_GAPS):
            if derived_status is AssessmentStatus.FAILED:
                raise IllegalStateTransition(
                    "no report can be generated: every scanner failed to complete for this "
                    "assessment, so no assessment data was collected",
                    current=derived_status,
                )
            raise IllegalStateTransition(
                "a report can only be generated from a completed assessment",
                current=derived_status,
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
            assessment_status=derived_status,
            profile_id=assessment.profile_id,
        )

    # --- convenience ---------------------------------------------------------
    @property
    def total_findings(self) -> int:
        return len(self.entries)

    @property
    def executive_score(self) -> float:
        """A single 0-100 aggregate score derived from the severity breakdown,
        computed under whichever formula this report was actually scored
        with (score_version) — never silently rescored under a newer
        formula just because one now exists."""
        if self.score_version == "v1":
            return compute_executive_score_v1(self.severity_counts)
        return compute_executive_score(self.severity_counts)

    def count_for(self, severity: Severity) -> int:
        """Number of findings at a given severity (0 if none)."""
        for level, count in self.severity_counts:
            if level is severity:
                return count
        return 0
