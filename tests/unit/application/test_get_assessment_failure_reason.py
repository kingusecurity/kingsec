"""Phase 03 reproduction + regression: failure_reason on AssessmentView.

Written FIRST, before any fix, per the Phase 03 remediation prompt's Step 3.
Run against the unmodified codebase, these fail because AssessmentView has no
failure_reason field at all - AssessmentView.from_domain() silently drops it
even though Assessment.fail() and the ORM both carry it correctly (verified
separately in tests/integration/persistence/test_assessment_repository.py's
TestMapping.test_round_trip_preserves_all_fields, which already passes).
"""

from __future__ import annotations

from tests.unit.application.conftest import InMemoryAssessmentRepository

from kingsec.application import GetAssessment, GetAssessmentRequest
from kingsec.domain import Assessment, Authorization, Target, TargetType


def _running(assessments: InMemoryAssessmentRepository) -> Assessment:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessment.start()
    assessments.save(assessment)
    return assessment


def _failed(assessments: InMemoryAssessmentRepository, reason: str) -> Assessment:
    assessment = _running(assessments)
    assessment.fail(reason)
    assessments.save(assessment)
    return assessment


def _completed(assessments: InMemoryAssessmentRepository) -> Assessment:
    assessment = _running(assessments)
    assessment.complete()
    assessments.save(assessment)
    return assessment


class TestAssessmentViewFailureReason:
    def test_failed_assessment_view_includes_failure_reason(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        assessment = _failed(assessments, "scanner subprocess exited with code 1")
        view = GetAssessment(assessments).execute(GetAssessmentRequest(str(assessment.id), is_admin=True))

        assert view.status == "failed"
        assert view.failure_reason == "scanner subprocess exited with code 1"

    def test_completed_assessment_failure_reason_is_none(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _completed(assessments)
        view = GetAssessment(assessments).execute(GetAssessmentRequest(str(assessment.id), is_admin=True))

        assert view.status == "completed"
        assert view.failure_reason is None

    def test_running_assessment_failure_reason_is_none(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _running(assessments)
        view = GetAssessment(assessments).execute(GetAssessmentRequest(str(assessment.id), is_admin=True))

        assert view.status == "running"
        assert view.failure_reason is None

    def test_failure_reason_with_special_characters_survives_unmodified(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        reason = 'connection refused: "10.0.0.99:443"\nretrying failed\ttab and unicode: café'
        assessment = _failed(assessments, reason)
        view = GetAssessment(assessments).execute(GetAssessmentRequest(str(assessment.id), is_admin=True))

        assert view.failure_reason == reason
