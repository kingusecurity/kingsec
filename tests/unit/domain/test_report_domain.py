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
from kingsec.domain.report import compute_executive_score, compute_executive_score_v1, generic_remediation_for

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


class TestStatusDerivedFromScannerSummary:
    """Phase 2C Step 2, GAP-1 fix: Report.assessment_status must be DERIVED
    from the assessment's own scanner_summary, not a passthrough of
    assessment.status - a persisted status can disagree with the scanner
    results it's supposed to summarize.

    Built the way the real defect actually arose - record a
    scanner_summary showing the true (bad) outcome, then call .complete()
    directly, exactly what an unconditional-complete() write path (e.g.
    the since-deleted StartAssessment use case) would do, bypassing the
    orchestrator's own success-counting decision - NOT via
    dataclasses.replace() on an already-correct Report. See CLAUDE.md's
    Verification honesty section: a test that hand-sets its own input can
    only verify what happens downstream of that input being correct: it
    never exercises whether the input is DERIVED correctly from real data,
    which is exactly the defect class this closes.
    """

    # The exact real shape of asmt-1983c7e4b1564815b62bb0bf02dc3e08 in
    # C:\kingsec-e2e\kingsec.db: status persisted as COMPLETED, but zero of
    # 5 scanners actually succeeded.
    _STALE_ROW_SUMMARY = (
        ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.PENDING),
        ScannerRunSummary(
            scanner_id="gobuster",
            name="Gobuster",
            status=ScannerRunState.FAILED,
            skipped_reason="wordlist could not be found",
        ),
        ScannerRunSummary(
            scanner_id="ffuf",
            name="FFUF",
            status=ScannerRunState.FAILED,
            skipped_reason="wordlist could not be found",
        ),
        ScannerRunSummary(
            scanner_id="zap",
            name="OWASP ZAP",
            status=ScannerRunState.FAILED,
            skipped_reason="scan process exited with an error",
        ),
        ScannerRunSummary(
            scanner_id="nuclei",
            name="Nuclei",
            status=ScannerRunState.SKIPPED_INCOMPATIBLE,
            skipped_reason="Missing Nuclei templates",
        ),
    )

    def test_zero_successes_refuses_a_scored_report_even_when_status_says_completed(self, running) -> None:
        """The actual stale-row fixture (asmt-1983c7e4b1564815b62bb0bf02dc3e08's
        real shape): record a scanner_summary showing zero successes, then
        call .complete() directly. assessment.status ends up COMPLETED;
        scanner_summary says otherwise. from_assessment() must refuse to
        build a scored report regardless."""
        running.record_scanner_summary(self._STALE_ROW_SUMMARY)
        running.complete()
        assert running.status.value == "completed"  # confirms the contradiction genuinely exists

        with pytest.raises(IllegalStateTransition, match="no report can be generated"):
            Report.from_assessment(running)

    def test_some_successes_derives_completed_with_gaps_despite_completed_status(self, running) -> None:
        """Same shape, but 4 of 5 scanners succeeded - the persisted status
        COMPLETED must not survive into the report; assessment_status must
        derive COMPLETED_WITH_GAPS from the real scanner data, so
        downstream rendering (the Partial Coverage override) fires from
        real data, not a hand-set field."""
        summary = (
            ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.SUCCEEDED, findings_count=1),
            ScannerRunSummary(scanner_id="gobuster", name="Gobuster", status=ScannerRunState.SUCCEEDED),
            ScannerRunSummary(scanner_id="ffuf", name="FFUF", status=ScannerRunState.SUCCEEDED),
            ScannerRunSummary(scanner_id="zap", name="OWASP ZAP", status=ScannerRunState.SUCCEEDED),
            ScannerRunSummary(scanner_id="nuclei", name="Nuclei", status=ScannerRunState.FAILED),
        )
        running.record_scanner_summary(summary)
        running.record_finding(make_finding(Severity.LOW))
        running.complete()  # the bug this reproduces: should have been complete_with_gaps()
        assert running.status.value == "completed"

        report = Report.from_assessment(running)
        assert report.assessment_status.value == "completed_with_gaps"

    def test_all_successes_confirms_completed_agrees_and_no_disagreement(self, running) -> None:
        """The non-buggy case: status and scanner_summary genuinely agree.
        Must not be affected by the derivation - same guarantee as before."""
        summary = (
            ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.SUCCEEDED, findings_count=1),
        )
        running.record_scanner_summary(summary)
        running.complete()

        report = Report.from_assessment(running)
        assert report.assessment_status.value == "completed"

    def test_no_scanner_summary_falls_back_to_persisted_status(self, running) -> None:
        """An assessment with no scanner_summary at all (pre-feature
        assessment, or a fixture that never calls record_scanner_summary())
        has nothing to derive from - must fall back to the persisted
        status exactly as before this fix."""
        running.complete()
        report = Report.from_assessment(running)
        assert report.assessment_status.value == "completed"


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


class TestExecutiveScoreV1:
    """compute_executive_score_v1: the deprecated linear-deduction formula,
    kept only to replay historical score_version="v1" reports exactly."""

    def test_no_findings_scores_100(self) -> None:
        assert compute_executive_score_v1(()) == 100.0

    def test_deducts_per_severity_weight(self) -> None:
        counts = ((Severity.CRITICAL, 1), (Severity.LOW, 2))
        # 100 - (1*25 + 2*2) = 71.0
        assert compute_executive_score_v1(counts) == 71.0

    def test_floors_at_zero(self) -> None:
        counts = ((Severity.CRITICAL, 10),)
        assert compute_executive_score_v1(counts) == 0.0

    def test_report_with_v1_score_version_uses_v1_formula(self, running) -> None:
        _complete(running, [make_finding(Severity.HIGH), make_finding(Severity.LOW)])
        report = dataclasses.replace(Report.from_assessment(running), score_version="v1")
        # 100 - (1*10 + 1*2) = 88.0
        assert report.executive_score == 88.0


class TestExecutiveScoreV2:
    """Phase 2C Step 2: compute_executive_score (v2) - the current,
    multiplicative retention model. Reference values are the Phase 2C
    Step 1 calibration report's own 8 verified values (docs/audits, and
    Downloads/KINGSEC-PHASE-2C-STEP1-CALIBRATION-REPORT.txt)."""

    @pytest.mark.parametrize(
        ("counts", "expected"),
        [
            ((), 100.0),
            (((Severity.LOW, 1),), 98.5),
            (((Severity.MEDIUM, 10),), 59.9),
            (((Severity.CRITICAL, 1),), 72.0),
            (((Severity.CRITICAL, 4),), 26.9),
            (((Severity.LOW, 50),), 47.0),
            (((Severity.LOW, 200),), 4.9),
            (
                (
                    (Severity.HIGH, 2),
                    (Severity.MEDIUM, 3),
                    (Severity.LOW, 20),
                    (Severity.INFORMATIONAL, 5),
                ),
                49.1,
            ),
        ],
    )
    def test_reference_values_exact(self, counts, expected) -> None:
        assert compute_executive_score(counts) == expected

    def test_report_defaults_to_v2(self, running) -> None:
        _complete(running, [make_finding(Severity.HIGH), make_finding(Severity.LOW)])
        report = Report.from_assessment(running)
        assert report.score_version == "v2"
        # retention: 0.88 * 0.985 = 0.8668 -> 86.68 -> rounds to 86.7
        assert report.executive_score == 86.7

    def test_informational_findings_never_change_the_score(self) -> None:
        baseline = ((Severity.CRITICAL, 1), (Severity.MEDIUM, 3), (Severity.LOW, 10))
        base_score = compute_executive_score(baseline)
        for info_count in (0, 1, 5, 100, 10_000):
            with_info = (*baseline, (Severity.INFORMATIONAL, info_count))
            assert compute_executive_score(with_info) == base_score

    @pytest.mark.parametrize(
        "counts",
        [
            ((Severity.CRITICAL, 1),),
            ((Severity.HIGH, 5),),
            ((Severity.MEDIUM, 20),),
            ((Severity.LOW, 50),),
            ((Severity.LOW, 100),),
            ((Severity.LOW, 189),),  # one below the first visible tie at N=190
            ((Severity.CRITICAL, 2), (Severity.HIGH, 3), (Severity.MEDIUM, 10), (Severity.LOW, 50)),
            ((Severity.CRITICAL, 1), (Severity.LOW, 1)),
        ],
    )
    def test_removing_a_finding_strictly_increases_score_below_underflow_threshold_n190(self, counts) -> None:
        """Strict monotonicity holds mathematically at any count (see
        _SCORE_RETENTION's docstring, domain/report.py), but stops being
        OBSERVABLE at the 1-decimal rendered score once two consecutive
        counts round identically - for an all-LOW distribution that first
        happens at N=190. This test is scoped to distributions below that
        point specifically so the property is checked where it's actually
        visible, not claimed past where it silently stops mattering."""
        before = compute_executive_score(counts)
        for i, (severity, _count) in enumerate(counts):
            reduced = tuple(
                (s, c - 1) if j == i else (s, c) for j, (s, c) in enumerate(counts)
            )
            reduced = tuple((s, c) for s, c in reduced if c > 0)
            after = compute_executive_score(reduced)
            assert after > before, f"removing one {severity.name} did not increase the score ({before} -> {after})"

    @pytest.mark.parametrize(
        "counts",
        [
            ((Severity.CRITICAL, 10_000),),
            ((Severity.HIGH, 10_000),),
            ((Severity.MEDIUM, 10_000),),
            ((Severity.LOW, 10_000),),
            ((Severity.INFORMATIONAL, 10_000),),
            (
                (Severity.CRITICAL, 2_500),
                (Severity.HIGH, 2_500),
                (Severity.MEDIUM, 2_500),
                (Severity.LOW, 2_500),
            ),
        ],
    )
    def test_score_stays_within_bounds_for_counts_up_to_10000(self, counts) -> None:
        score = compute_executive_score(counts)
        assert 0.0 <= score <= 100.0


class TestGenericRemediation:
    def test_open_port_gets_generic_guidance(self) -> None:
        rec = generic_remediation_for("Open port 445/tcp", Severity.LOW)
        assert rec is not None
        assert "firewall" in rec.description.lower()
        assert rec.priority is Severity.LOW  # mirrors the finding's own severity

    def test_unknown_finding_type_below_high_returns_none(self) -> None:
        # Never fabricate guidance for finding types not in the curated
        # tables - below Critical/High, where FIX 1's unconditional
        # guidance requirement does not apply, this still stays honest.
        assert generic_remediation_for("Some exotic zero-day finding", Severity.MEDIUM) is None
        assert generic_remediation_for("Some exotic zero-day finding", Severity.LOW) is None
        assert generic_remediation_for("Some exotic zero-day finding", Severity.INFORMATIONAL) is None

    def test_cwe_798_gets_hardcoded_credentials_guidance(self) -> None:
        """Phase 2C Step 2, FIX 1: the exact real-data regression this fix
        closes - a nuclei dvwa-default-login match (CWE-798) with no
        scanner-supplied remediation must no longer render silence."""
        rec = generic_remediation_for("DVWA Default Login", Severity.CRITICAL, cwe_ids=("CWE-798",))
        assert rec is not None
        assert "credential" in rec.description.lower()
        assert rec.priority is Severity.CRITICAL

    def test_cwe_lookup_is_case_insensitive(self) -> None:
        # Real captured Nuclei output has shown lower-case "cwe-693" for the
        # same classification a template's YAML declares as "CWE-693".
        rec = generic_remediation_for("HTTP Missing Security Headers", Severity.INFORMATIONAL, cwe_ids=("cwe-693",))
        assert rec is not None
        assert "protection mechanism" in rec.description.lower()

    def test_all_evidence_cwes_are_covered(self) -> None:
        """FIX 1: 'Cover at minimum the CWEs actually observed in our
        evidence (798, 200, 614, 1004, 693).'"""
        for cwe in ("CWE-798", "CWE-200", "CWE-614", "CWE-1004", "CWE-693"):
            assert generic_remediation_for("Some finding", Severity.MEDIUM, cwe_ids=(cwe,)) is not None

    def test_unmatched_cwe_falls_through_to_severity_fallback_for_high(self) -> None:
        rec = generic_remediation_for("Some exotic zero-day finding", Severity.HIGH, cwe_ids=("CWE-9999",))
        assert rec is not None

    def test_critical_or_high_never_returns_none_even_with_no_cwe(self) -> None:
        # FIX 1's unconditional requirement: "Never render 'no guidance
        # available' for a Critical or High finding" - even one with no
        # CWE at all and no title-prefix match.
        assert generic_remediation_for("Some exotic zero-day finding", Severity.CRITICAL) is not None
        assert generic_remediation_for("Some exotic zero-day finding", Severity.HIGH) is not None

    def test_severity_fallback_is_honest_not_a_fabricated_technical_fix(self) -> None:
        rec = generic_remediation_for("Some exotic zero-day finding", Severity.CRITICAL)
        assert rec is not None
        assert "no specific automated remediation guidance is available" in rec.description.lower()

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


# Phase 2C Step 2, FIX 2: TestEstimatedEffort removed along with
# FindingSummary.estimated_effort itself - a severity-based effort
# heuristic (e.g. "Large" for changing a default password) is not
# grounded in any real data and was visibly wrong on a real report;
# removed rather than replaced with a differently-shaped guess.


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


class TestProfileId:
    """Phase 6 Task 5: Assessment.profile_id was always real and set at
    creation time - from_assessment() simply never copied it onto Report
    before. Tests the actual copy-through end to end (a real Assessment
    built with a real profile_id, not a dataclasses.replace() shortcut
    that would only prove the field exists, not that it's populated
    correctly)."""

    def test_profile_id_copied_from_a_real_assessment(self) -> None:
        from datetime import UTC, datetime

        from kingsec.domain import Assessment, Authorization, Target, TargetType

        assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS), profile_id="web-scan")
        assessment.authorize(Authorization("tester", datetime.now(UTC), scope="10.0.0.5"))
        assessment.start()
        assessment.complete()
        report = Report.from_assessment(assessment)
        assert report.profile_id == "web-scan"

    def test_no_profile_selected_stays_none(self) -> None:
        from datetime import UTC, datetime

        from kingsec.domain import Assessment, Authorization, Target, TargetType

        assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))  # profile_id defaults to None
        assessment.authorize(Authorization("tester", datetime.now(UTC), scope="10.0.0.5"))
        assessment.start()
        assessment.complete()
        report = Report.from_assessment(assessment)
        assert report.profile_id is None
