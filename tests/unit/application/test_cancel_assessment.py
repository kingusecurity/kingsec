"""CancelAssessment use case: cancellation gates and error handling."""

from __future__ import annotations

import pytest
from tests.unit.application.conftest import InMemoryAssessmentRepository

from kingsec.application import (
    AssessmentNotFoundError,
    CancelAssessment,
    CancelAssessmentRequest,
)
from kingsec.domain import (
    Assessment,
    AssessmentStatus,
    Authorization,
    IllegalStateTransition,
    Target,
    TargetType,
)


def _draft(assessments: InMemoryAssessmentRepository) -> Assessment:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessments.save(assessment)
    return assessment


def _authorized(assessments: InMemoryAssessmentRepository) -> Assessment:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessments.save(assessment)
    return assessment


def _running(assessments: InMemoryAssessmentRepository) -> Assessment:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessment.start()
    assessments.save(assessment)
    return assessment


def _completed(assessments: InMemoryAssessmentRepository) -> Assessment:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessment.start()
    assessment.complete()
    assessments.save(assessment)
    return assessment


def _failed(assessments: InMemoryAssessmentRepository) -> Assessment:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessment.start()
    assessment.fail("scanner crashed")
    assessments.save(assessment)
    return assessment


class TestCancelDraftAssessment:
    def test_cancels_draft_assessment(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _draft(assessments)
        use_case = CancelAssessment(assessments)

        response = use_case.execute(CancelAssessmentRequest(str(assessment.id)))

        assert response.assessment_id == str(assessment.id)
        assert response.status == AssessmentStatus.CANCELLED.value

        stored = assessments.get(assessment.id)
        assert stored.status == AssessmentStatus.CANCELLED


class TestCancelAuthorizedAssessment:
    def test_cancels_authorized_assessment(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _authorized(assessments)
        use_case = CancelAssessment(assessments)

        response = use_case.execute(CancelAssessmentRequest(str(assessment.id)))

        assert response.status == AssessmentStatus.CANCELLED.value

        stored = assessments.get(assessment.id)
        assert stored.status == AssessmentStatus.CANCELLED


class TestCancelRunningAssessment:
    def test_cancels_running_assessment(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _running(assessments)
        use_case = CancelAssessment(assessments)

        response = use_case.execute(CancelAssessmentRequest(str(assessment.id)))

        assert response.status == AssessmentStatus.CANCELLED.value

        stored = assessments.get(assessment.id)
        assert stored.status == AssessmentStatus.CANCELLED


class TestCancelTerminalAssessments:
    def test_cannot_cancel_completed_assessment(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _completed(assessments)
        use_case = CancelAssessment(assessments)

        with pytest.raises(IllegalStateTransition):
            use_case.execute(CancelAssessmentRequest(str(assessment.id)))

    def test_cannot_cancel_failed_assessment(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _failed(assessments)
        use_case = CancelAssessment(assessments)

        with pytest.raises(IllegalStateTransition):
            use_case.execute(CancelAssessmentRequest(str(assessment.id)))

    def test_cannot_cancel_already_cancelled_assessment(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _draft(assessments)
        use_case = CancelAssessment(assessments)

        # First cancel succeeds
        use_case.execute(CancelAssessmentRequest(str(assessment.id)))

        # Second cancel fails
        with pytest.raises(IllegalStateTransition):
            use_case.execute(CancelAssessmentRequest(str(assessment.id)))


class TestCancelNotFound:
    def test_nonexistent_assessment_raises(self, assessments: InMemoryAssessmentRepository) -> None:
        use_case = CancelAssessment(assessments)

        with pytest.raises(AssessmentNotFoundError):
            use_case.execute(CancelAssessmentRequest("asmt-does-not-exist"))
