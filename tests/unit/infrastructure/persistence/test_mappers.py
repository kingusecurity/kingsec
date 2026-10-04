"""Unit tests for the mapping layer (no database).

Because ``*_to_orm`` builds ORM objects with their child collections populated in
memory, and ``*_to_domain`` reads those same in-memory collections, we can verify
the full mapping + reconstitution logic without ever touching a session.
"""

from __future__ import annotations

from kingsec.domain import (
    AssessmentStatus,
    FindingStatus,
    Report,
    Severity,
)
from kingsec.infrastructure.persistence.mappers import (
    assessment_to_domain,
    assessment_to_orm,
    report_to_domain,
    report_to_orm,
)
from tests.unit.infrastructure.persistence.conftest import completed_assessment


class TestAssessmentMapping:
    def test_round_trip_preserves_aggregate(self) -> None:
        original = completed_assessment()

        restored = assessment_to_domain(assessment_to_orm(original))

        assert restored.id == original.id
        assert restored.status is AssessmentStatus.COMPLETED
        assert str(restored.target) == str(original.target)
        assert restored.created_at == original.created_at
        assert len(restored.findings) == 2

    def test_round_trip_preserves_authorization(self) -> None:
        original = completed_assessment()
        restored = assessment_to_domain(assessment_to_orm(original))

        assert restored.is_authorized is True
        assert restored.authorization is not None
        assert restored.authorization.authorized_by == "tester"
        # Timezone-aware timestamp survives the ISO string round-trip.
        assert restored.authorization.authorized_at.tzinfo is not None

    def test_round_trip_preserves_finding_details(self) -> None:
        original = completed_assessment()
        restored = assessment_to_domain(assessment_to_orm(original))

        by_title = {f.title: f for f in restored.findings}
        sqli = by_title["SQL Injection"]
        assert sqli.severity is Severity.CRITICAL
        assert sqli.status is FindingStatus.CONFIRMED
        assert len(sqli.evidence) == 1
        assert sqli.evidence[0].summary == "payload"
        assert len(sqli.recommendations) == 1
        assert sqli.recommendations[0].priority is Severity.CRITICAL


class TestReportMapping:
    def test_round_trip_preserves_report(self) -> None:
        report = Report.from_assessment(completed_assessment())

        restored = report_to_domain(report_to_orm(report))

        assert restored.assessment_id == report.assessment_id
        assert restored.verdict.headline == report.verdict.headline
        assert restored.verdict.highest_severity is Severity.CRITICAL
        assert restored.verdict.action_required is True
        assert restored.total_findings == 2
        assert restored.count_for(Severity.CRITICAL) == 1
        assert restored.count_for(Severity.LOW) == 1
        # Entries stay ordered worst-first after the JSON round-trip.
        assert restored.entries[0].severity is Severity.CRITICAL


class TestFindingAffectedAssetMapping:
    """affected_asset survives the ORM round-trip; absence stays absent."""

    def test_round_trip_preserves_affected_asset(self) -> None:
        from kingsec.domain import Finding
        from kingsec.infrastructure.persistence.mappers import finding_to_domain, finding_to_orm

        finding = Finding.create(
            "Open port 3389/tcp",
            "Port 3389/tcp is open",
            Severity.HIGH,
            affected_asset="10.0.0.9",
        )
        restored = finding_to_domain(finding_to_orm(finding))
        assert restored.affected_asset == "10.0.0.9"

    def test_round_trip_preserves_absent_affected_asset(self) -> None:
        from kingsec.domain import Finding
        from kingsec.infrastructure.persistence.mappers import finding_to_domain, finding_to_orm

        finding = Finding.create("Missing headers", "no CSP", Severity.LOW)
        restored = finding_to_domain(finding_to_orm(finding))
        assert restored.affected_asset is None

    def test_report_json_round_trip_preserves_affected_asset(self) -> None:
        from kingsec.domain import Assessment, Authorization, Finding, Target, TargetType
        from kingsec.infrastructure.persistence.mappers import report_to_domain, report_to_orm
        from tests.unit.infrastructure.persistence.conftest import utc

        assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
        assessment.authorize(Authorization("tester", utc(), scope="10.0.0.5"))
        assessment.start()
        assessment.record_finding(
            Finding.create(
                "Open port 3389/tcp",
                "Port 3389/tcp is open",
                Severity.HIGH,
                affected_asset="10.0.0.9",
            )
        )
        assessment.complete()

        report = Report.from_assessment(assessment)
        restored = report_to_domain(report_to_orm(report))
        assert restored.entries[0].affected_asset == "10.0.0.9"
