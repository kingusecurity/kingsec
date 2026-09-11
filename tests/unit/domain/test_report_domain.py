"""Report snapshot: generation guard, verdict derivation, ordering, immutability."""

from __future__ import annotations

import dataclasses

import pytest
from tests.unit.domain.conftest import make_finding

from kingsec.domain import (
    IllegalStateTransition,
    Report,
    ScannerRunSummary,
    Severity,
)
from kingsec.domain.enums import ScannerRunState
from kingsec.domain.report import compute_executive_score, generic_remediation_for

# Old (pre-Phase-2A) string vocabulary -> ScannerRunState, for the test
# helpers/fixtures below that still spell statuses the old way.
_STATUS_MAP = {
    "completed": ScannerRunState.SUCCEEDED,
    "failed": ScannerRunState.FAILED,
    "skipped": ScannerRunState.SKIPPED_INCOMPATIBLE,
    "pending": ScannerRunState.PENDING,
}


def _complete(running, findings) -> None:
    for f in findings:
        running.record_finding(f)
    running.complete()


class TestGenerationGuard:
    def test_requires_completed_assessment(self, running) -> None:
        # Still RUNNING -> not allowed.
        with pytest.raises(IllegalStateTransition, match="completed assessment"):
            Report.from_assessment(running)

    def test_generates_from_completed(self, running) -> None:
        _complete(running, [make_finding(Severity.HIGH)])
        report = Report.from_assessment(running)
        assert report.total_findings == 1
        assert report.assessment_id == str(running.id)


class TestVerdict:
    def test_clean_verdict_when_no_findings(self, running) -> None:
        running.complete()
        report = Report.from_assessment(running)
        assert report.verdict.highest_severity is None
        assert report.verdict.action_required is False
        assert "No security issues" in report.verdict.headline

    def test_verdict_uses_highest_severity(self, running) -> None:
        _complete(running, [make_finding(Severity.LOW), make_finding(Severity.CRITICAL)])
        report = Report.from_assessment(running)
        assert report.verdict.highest_severity is Severity.CRITICAL
        assert report.verdict.action_required is True
        assert "Critical" in report.verdict.headline

    def test_false_positives_are_excluded_from_verdict(self, running) -> None:
        critical = make_finding(Severity.CRITICAL)
        low = make_finding(Severity.LOW)
        running.record_finding(critical)
        running.record_finding(low)
        critical.mark_false_positive()  # dismiss the worst one
        running.complete()

        report = Report.from_assessment(running)
        # Verdict ignores the false positive, so LOW drives it...
        assert report.verdict.highest_severity is Severity.LOW
        # ...but the honest counts still include the dismissed finding.
        assert report.count_for(Severity.CRITICAL) == 1
        assert report.total_findings == 2


def _summary(scanner_id: str, name: str, status: str, findings_count: int = 0) -> ScannerRunSummary:
    return ScannerRunSummary(scanner_id=scanner_id, name=name, status=_STATUS_MAP[status], findings_count=findings_count)


# Phase 09 Scenario 3's exact live shape: one scanner completed with
# informational findings, four failed with binary-absent (see Phase 09
# report, docs/audits/KINGSEC-PHASE-09-CONSOLIDATION-VERIFICATION-REPORT.md
# section 5, Scenario 3 - captured verbatim from the real deployed container).
_SCENARIO_3_SUMMARY = (
    _summary("nuclei", "Nuclei Scanner", "completed", findings_count=7),
    _summary("nikto", "Nikto Scanner", "failed"),
    _summary("ffuf", "ffuf Scanner", "failed"),
    _summary("gobuster", "Gobuster Scanner", "failed"),
    _summary("zap", "OWASP ZAP", "failed"),
)


class TestPartialCoverageVerdict:
    """Phase 10: a partially-executed assessment must not present as an
    unqualified clean result. See docs/audits/
    KINGSEC-PHASE-10-PARTIAL-SCAN-HONESTY-REPORT.md.
    """

    def test_scenario_3_shape_no_longer_reads_as_unqualified_clean(self, running) -> None:
        """The exact live defect from Phase 09 Scenario 3: one scanner
        completed with 7 informational findings, four failed with
        binary-absent - the verdict said "no action required" about a scan
        that mostly didn't run."""
        findings = [make_finding(Severity.INFORMATIONAL, title=f"Finding {i}") for i in range(7)]
        for f in findings:
            running.record_finding(f)
        running.record_scanner_summary(_SCENARIO_3_SUMMARY)
        running.complete()

        report = Report.from_assessment(running)
        assert report.verdict.action_required is True
        assert "no action required" not in report.verdict.headline.lower()

    def test_all_completed_zero_findings_stays_unqualified(self, running) -> None:
        """The signal must be specific, not blanket: a genuinely clean,
        fully-executed scan must still read as clean."""
        running.record_scanner_summary(
            (_summary("nuclei", "Nuclei Scanner", "completed"), _summary("nmap", "Nmap Scanner", "completed"))
        )
        running.complete()

        report = Report.from_assessment(running)
        assert report.verdict.action_required is False
        assert report.verdict.headline == "No security issues identified."

    def test_all_completed_findings_present_verdict_unchanged(self, running) -> None:
        running.record_finding(make_finding(Severity.CRITICAL))
        running.record_scanner_summary(
            (_summary("nuclei", "Nuclei Scanner", "completed", findings_count=1),)
        )
        running.complete()

        report = Report.from_assessment(running)
        assert report.verdict.highest_severity is Severity.CRITICAL
        assert report.verdict.action_required is True
        assert "Critical" in report.verdict.headline
        assert "did not complete" not in report.verdict.headline

    def test_some_failed_findings_present_is_qualified(self, running) -> None:
        running.record_finding(make_finding(Severity.HIGH))
        running.record_scanner_summary(
            (
                _summary("nuclei", "Nuclei Scanner", "completed", findings_count=1),
                _summary("nmap", "Nmap Scanner", "failed"),
            )
        )
        running.complete()

        report = Report.from_assessment(running)
        assert report.verdict.action_required is True
        assert "did not complete" in report.verdict.headline
        assert "Nmap Scanner" in report.verdict.headline

    def test_some_failed_zero_findings_is_qualified(self, running) -> None:
        """The most dangerous case: no findings and no indication that most
        of the scan didn't run."""
        running.record_scanner_summary(
            (
                _summary("nuclei", "Nuclei Scanner", "completed"),
                _summary("nmap", "Nmap Scanner", "failed"),
                _summary("nikto", "Nikto Scanner", "failed"),
            )
        )
        running.complete()

        report = Report.from_assessment(running)
        assert report.verdict.action_required is True
        assert "did not complete" in report.verdict.headline
        assert report.verdict.headline != "No security issues identified."

    def test_non_applicable_scanners_only_not_qualified(self, running) -> None:
        """A scanner that was never applicable to this target (absent from
        scanner_summary entirely - Phase 09 Scenario 3's own observed
        behavior for Amass/Trivy/Semgrep against a URL target) did not fail
        to run, and must not count toward incompleteness."""
        running.record_scanner_summary((_summary("nuclei", "Nuclei Scanner", "completed"),))
        running.complete()

        report = Report.from_assessment(running)
        assert report.verdict.action_required is False
        assert report.verdict.headline == "No security issues identified."

    def test_preplanned_skip_is_qualified(self, running) -> None:
        """Phase 2A FIX 6 (already-decided, unchanged by this phase)
        superseded this Phase 10 assumption: a skipped scanner is still,
        honestly, a scanner whose coverage this assessment does not have
        (the Run #4 reference case is exactly six scanners skipped, none
        of them literally "failed" in the old narrow sense). Only a fully
        SUCCEEDED scanner set is unqualified now."""
        running.record_scanner_summary(
            (
                _summary("nuclei", "Nuclei Scanner", "completed"),
                ScannerRunSummary(
                    scanner_id="amass",
                    name="Amass",
                    status=ScannerRunState.SKIPPED_INCOMPATIBLE,
                    skipped_reason="not applicable to this profile",
                ),
            )
        )
        running.complete()

        report = Report.from_assessment(running)
        assert report.verdict.action_required is True
        assert "Amass" in report.verdict.headline

    def test_all_attempted_failed_stays_failed_no_report(self, running) -> None:
        """Phase 06's policy is unchanged: an assessment where every
        attempted scanner failed transitions to FAILED, not COMPLETED, and
        a report can never be generated from it."""
        running.record_scanner_summary(
            (_summary("nuclei", "Nuclei Scanner", "failed"), _summary("nmap", "Nmap Scanner", "failed"))
        )
        running.fail("All 2 configured scanners failed to complete: Nuclei Scanner, Nmap Scanner.")

        # Phase 2A FIX 5 gives the FAILED case its own specific, honest
        # message (superseding the old generic "completed assessment"
        # text) - there is no real data to report on, so from_assessment
        # says exactly that rather than a generic state-transition error.
        with pytest.raises(IllegalStateTransition, match="no report can be generated"):
            Report.from_assessment(running)

    def test_qualified_headline_leaks_no_raw_exception_text(self, running) -> None:
        """Mirrors Phase 08 §6's per-mode leak assertions: the new
        coverage-caveat text interpolates only scanner display names and
        counts (Phase 08 §2's explicit safe list) - never a path, binary
        location, command line, internal hostname, or raw str(exc)."""
        running.record_scanner_summary(
            (
                _summary("nuclei", "Nuclei Scanner", "completed"),
                ScannerRunSummary(
                    scanner_id="nmap", name="Nmap Scanner", status=ScannerRunState.FAILED, findings_count=0
                ),
            )
        )
        running.complete()

        headline = Report.from_assessment(running).verdict.headline
        assert "/" not in headline  # no filesystem paths
        assert "Traceback" not in headline
        assert "Exception" not in headline
        assert "nmap exited with code" not in headline  # raw internal message text

    def test_informational_findings_and_incomplete_does_not_say_no_action_required(self, running) -> None:
        """Even when the only findings are Informational (which alone would
        say 'no action required' today), incomplete coverage must still
        flip action_required and drop that specific claim."""
        running.record_finding(make_finding(Severity.INFORMATIONAL))
        running.record_scanner_summary(
            (
                _summary("nuclei", "Nuclei Scanner", "completed", findings_count=1),
                _summary("nmap", "Nmap Scanner", "failed"),
            )
        )
        running.complete()

        report = Report.from_assessment(running)
        assert report.verdict.action_required is True
        assert "no action required" not in report.verdict.headline.lower()


class TestOrderingAndCounts:
    def test_entries_are_ordered_worst_first(self, running) -> None:
        _complete(
            running,
            [make_finding(Severity.LOW), make_finding(Severity.CRITICAL), make_finding(Severity.MEDIUM)],
        )
        report = Report.from_assessment(running)
        severities = [entry.severity for entry in report.entries]
        assert severities == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]

    def test_severity_counts(self, running) -> None:
        _complete(
            running,
            [make_finding(Severity.HIGH), make_finding(Severity.HIGH), make_finding(Severity.LOW)],
        )
        report = Report.from_assessment(running)
        assert report.count_for(Severity.HIGH) == 2
        assert report.count_for(Severity.LOW) == 1
        assert report.count_for(Severity.CRITICAL) == 0

    def test_entry_snapshots_evidence_and_recommendation_counts(self, running) -> None:
        from kingsec.domain import Evidence, Recommendation

        finding = make_finding(Severity.HIGH)
        finding.add_evidence(Evidence.create("resp", "detail"))
        finding.add_recommendation(Recommendation("Patch", "Upgrade", Severity.HIGH))
        _complete(running, [finding])

        entry = Report.from_assessment(running).entries[0]
        assert entry.evidence_count == 1
        assert entry.recommendation_count == 1


class TestExecutiveScore:
    def test_no_findings_scores_100(self) -> None:
        assert compute_executive_score(()) == 100.0

    def test_deducts_per_severity_weight(self) -> None:
        counts = ((Severity.CRITICAL, 1), (Severity.LOW, 2))
        # 100 - (1*25 + 2*2) = 71.0
        assert compute_executive_score(counts) == 71.0

    def test_floors_at_zero(self) -> None:
        counts = ((Severity.CRITICAL, 10),)
        assert compute_executive_score(counts) == 0.0

    def test_report_exposes_matching_score(self, running) -> None:
        _complete(running, [make_finding(Severity.HIGH), make_finding(Severity.LOW)])
        report = Report.from_assessment(running)
        # 100 - (1*10 + 1*2) = 88.0
        assert report.executive_score == 88.0


class TestGenericRemediation:
    def test_open_port_gets_generic_guidance(self) -> None:
        rec = generic_remediation_for("Open port 445/tcp", Severity.LOW)
        assert rec is not None
        assert "firewall" in rec.description.lower()
        assert rec.priority is Severity.LOW  # mirrors the finding's own severity

    def test_unknown_finding_type_returns_none(self) -> None:
        # Never fabricate guidance for finding types not in the curated table.
        assert generic_remediation_for("Some exotic zero-day finding", Severity.HIGH) is None

    def test_finding_summary_falls_back_when_no_real_recommendation(self, running) -> None:
        finding = make_finding(Severity.LOW, title="Open port 22/tcp")
        _complete(running, [finding])
        entry = Report.from_assessment(running).entries[0]
        assert entry.recommendations == ()  # no real (AI/analyst) recommendation
        assert len(entry.effective_recommendations) == 1
        assert entry.effective_recommendations[0].title.startswith("Review whether")

    def test_finding_summary_prefers_real_recommendation_over_generic(self, running) -> None:
        from kingsec.domain import Recommendation

        finding = make_finding(Severity.LOW, title="Open port 22/tcp")
        finding.add_recommendation(Recommendation("Real fix", "Use a real analyst note", Severity.LOW))
        _complete(running, [finding])
        entry = Report.from_assessment(running).entries[0]
        assert entry.effective_recommendations == entry.recommendations
        assert entry.effective_recommendations[0].title == "Real fix"

    def test_unmatched_finding_type_has_no_effective_recommendations(self, running) -> None:
        finding = make_finding(Severity.LOW, title="Some exotic zero-day finding")
        _complete(running, [finding])
        entry = Report.from_assessment(running).entries[0]
        assert entry.effective_recommendations == ()


class TestEstimatedEffort:
    def test_critical_and_high_are_large(self, running) -> None:
        _complete(running, [make_finding(Severity.CRITICAL), make_finding(Severity.HIGH)])
        report = Report.from_assessment(running)
        assert all(entry.estimated_effort == "Large" for entry in report.entries)

    def test_medium_is_medium(self, running) -> None:
        _complete(running, [make_finding(Severity.MEDIUM)])
        report = Report.from_assessment(running)
        assert report.entries[0].estimated_effort == "Medium"

    def test_low_and_informational_are_small(self, running) -> None:
        _complete(running, [make_finding(Severity.LOW), make_finding(Severity.INFORMATIONAL)])
        report = Report.from_assessment(running)
        assert all(entry.estimated_effort == "Small" for entry in report.entries)


class TestAuthorizationMetadata:
    def test_captures_authorized_by_and_scope(self, running) -> None:
        running.complete()
        report = Report.from_assessment(running)
        assert report.authorized_by == "pentester@kingusecurity.com"
        assert report.scope == "10.0.0.5"


class TestHistory:
    def test_from_assessment_never_touches_history_or_ai(self, running) -> None:
        # from_assessment is pure domain — history/AI are attached later, in
        # the GenerateReport use case, never here.
        running.complete()
        report = Report.from_assessment(running)
        assert report.history == ()
        assert report.ai_enabled is False


class TestImmutability:
    def test_report_is_frozen(self, running) -> None:
        running.complete()
        report = Report.from_assessment(running)
        with pytest.raises(dataclasses.FrozenInstanceError):
            report.target = "changed"  # type: ignore[misc]
