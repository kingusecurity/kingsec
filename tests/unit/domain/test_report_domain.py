"""Report snapshot: generation guard, verdict derivation, ordering, immutability."""

from __future__ import annotations

import dataclasses

import pytest
from tests.unit.domain.conftest import make_finding

from kingsec.domain import (
    IllegalStateTransition,
    Report,
    Severity,
)
from kingsec.domain.report import compute_executive_score, generic_remediation_for


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
