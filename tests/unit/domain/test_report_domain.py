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


class TestImmutability:
    def test_report_is_frozen(self, running) -> None:
        running.complete()
        report = Report.from_assessment(running)
        with pytest.raises(dataclasses.FrozenInstanceError):
            report.target = "changed"  # type: ignore[misc]
