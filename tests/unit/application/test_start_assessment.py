"""StartAssessment use case: gate, scanning, enrichment, resilience."""

from __future__ import annotations

import pytest
from tests.unit.application.conftest import (
    FailingAI,
    InMemoryAssessmentRepository,
    StubAI,
    StubScanner,
    make_findings,
)

from kingsec.application import (
    AssessmentNotFoundError,
    StartAssessment,
    StartAssessmentRequest,
)
from kingsec.domain import (
    Assessment,
    AssessmentStatus,
    Authorization,
    IllegalStateTransition,
    Severity,
    Target,
    TargetType,
)


def _authorized(assessments: InMemoryAssessmentRepository) -> Assessment:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessments.save(assessment)
    return assessment


def _draft(assessments: InMemoryAssessmentRepository) -> Assessment:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessments.save(assessment)  # never authorized
    return assessment


class TestHappyPath:
    def test_runs_scan_records_findings_and_completes(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _authorized(assessments)
        use_case = StartAssessment(assessments, StubScanner(make_findings()), StubAI())

        response = use_case.execute(StartAssessmentRequest(str(assessment.id)))

        assert response.status == AssessmentStatus.COMPLETED.value
        assert response.findings_count == 2
        assert response.highest_severity == Severity.CRITICAL.label

        stored = assessments.get(assessment.id)
        # AI enrichment attached a recommendation to each finding.
        assert all(f.recommendations for f in stored.findings)


class TestAuthorizationGate:
    def test_cannot_start_unauthorized_assessment(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _draft(assessments)
        use_case = StartAssessment(assessments, StubScanner(make_findings()))

        # The domain gate fires and the use case lets it propagate.
        with pytest.raises(IllegalStateTransition):
            use_case.execute(StartAssessmentRequest(str(assessment.id)))


class TestErrors:
    def test_unknown_assessment_raises_not_found(self, assessments: InMemoryAssessmentRepository) -> None:
        use_case = StartAssessment(assessments, StubScanner([]))
        with pytest.raises(AssessmentNotFoundError):
            use_case.execute(StartAssessmentRequest("asmt-does-not-exist"))


class TestAiResilience:
    def test_ai_failure_does_not_fail_the_scan(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _authorized(assessments)
        use_case = StartAssessment(assessments, StubScanner(make_findings()), FailingAI())

        response = use_case.execute(StartAssessmentRequest(str(assessment.id)))

        # Scan still completes; findings recorded, just without AI recommendations.
        assert response.status == AssessmentStatus.COMPLETED.value
        assert response.findings_count == 2
        stored = assessments.get(assessment.id)
        assert all(not f.recommendations for f in stored.findings)

    def test_runs_without_any_ai_port(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _authorized(assessments)
        use_case = StartAssessment(assessments, StubScanner(make_findings()))  # ai=None
        response = use_case.execute(StartAssessmentRequest(str(assessment.id)))
        assert response.findings_count == 2
