"""DeleteAssessment use case: deletion, not-found, repository behavior."""

from __future__ import annotations

import pytest
from tests.unit.application.conftest import InMemoryAssessmentRepository

from kingsec.application import (
    AssessmentNotFoundError,
    DeleteAssessment,
    DeleteAssessmentRequest,
    DeleteAssessmentResponse,
)
from kingsec.domain import (
    Assessment,
    AssessmentStatus,
    Authorization,
    Finding,
    Severity,
    Target,
    TargetType,
)


def _make_assessment(
    *,
    target_value: str = "10.0.0.5",
    with_findings: bool = False,
) -> Assessment:
    assessment = Assessment.create(Target(target_value, TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope=target_value))
    if with_findings:
        assessment.start()
        assessment.record_finding(Finding.create("SQLi", "injectable", Severity.CRITICAL))
        assessment.complete()
    return assessment


class TestDeleteExistingAssessment:
    def test_deletes_assessment(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _make_assessment()
        assessments.save(assessment)

        use_case = DeleteAssessment(assessments)
        response = use_case.execute(DeleteAssessmentRequest(str(assessment.id), is_admin=True))

        assert isinstance(response, DeleteAssessmentResponse)
        assert response.assessment_id == str(assessment.id)

        # Verify it's gone
        with pytest.raises(AssessmentNotFoundError):
            assessments.get(assessment.id)

    def test_deletes_assessment_with_findings(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _make_assessment(with_findings=True)
        assessments.save(assessment)

        use_case = DeleteAssessment(assessments)
        response = use_case.execute(DeleteAssessmentRequest(str(assessment.id), is_admin=True))

        assert response.assessment_id == str(assessment.id)

        # Verify it's gone
        with pytest.raises(AssessmentNotFoundError):
            assessments.get(assessment.id)

    def test_deletes_only_target_assessment(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment1 = _make_assessment(target_value="10.0.0.1")
        assessment2 = _make_assessment(target_value="10.0.0.2")
        assessments.save(assessment1)
        assessments.save(assessment2)

        use_case = DeleteAssessment(assessments)
        use_case.execute(DeleteAssessmentRequest(str(assessment1.id), is_admin=True))

        # assessment1 is gone, assessment2 still exists
        with pytest.raises(AssessmentNotFoundError):
            assessments.get(assessment1.id)

        loaded = assessments.get(assessment2.id)
        assert loaded.status == AssessmentStatus.AUTHORIZED


class TestDeleteMissingAssessment:
    def test_nonexistent_assessment_raises(self, assessments: InMemoryAssessmentRepository) -> None:
        use_case = DeleteAssessment(assessments)

        with pytest.raises(AssessmentNotFoundError):
            use_case.execute(DeleteAssessmentRequest("asmt-does-not-exist", is_admin=True))

    def test_double_delete_raises(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _make_assessment()
        assessments.save(assessment)

        use_case = DeleteAssessment(assessments)
        use_case.execute(DeleteAssessmentRequest(str(assessment.id), is_admin=True))

        # Second delete should raise not found
        with pytest.raises(AssessmentNotFoundError):
            use_case.execute(DeleteAssessmentRequest(str(assessment.id), is_admin=True))


class TestDeleteRepositoryBehavior:
    def test_list_excludes_deleted_assessment(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment1 = _make_assessment(target_value="10.0.0.1")
        assessment2 = _make_assessment(target_value="10.0.0.2")
        assessments.save(assessment1)
        assessments.save(assessment2)

        use_case = DeleteAssessment(assessments)
        use_case.execute(DeleteAssessmentRequest(str(assessment1.id), is_admin=True))

        remaining = assessments.list().items
        assert len(remaining) == 1
        assert remaining[0].id == assessment2.id

    def test_empty_repository_after_deleting_all(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _make_assessment()
        assessments.save(assessment)

        use_case = DeleteAssessment(assessments)
        use_case.execute(DeleteAssessmentRequest(str(assessment.id), is_admin=True))

        remaining = assessments.list().items
        assert remaining == ()


class TestDeleteAccessControl:
    def test_non_owner_gets_not_found(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _make_assessment()
        assessment.set_ownership("alice")
        assessments.save(assessment)

        use_case = DeleteAssessment(assessments)
        with pytest.raises(AssessmentNotFoundError):
            use_case.execute(
                DeleteAssessmentRequest(str(assessment.id), requesting_user="bob", is_admin=False)
            )

        # Not actually deleted
        assert assessments.get(assessment.id) is not None

    def test_owner_can_delete(self, assessments: InMemoryAssessmentRepository) -> None:
        assessment = _make_assessment()
        assessment.set_ownership("alice")
        assessments.save(assessment)

        use_case = DeleteAssessment(assessments)
        response = use_case.execute(
            DeleteAssessmentRequest(str(assessment.id), requesting_user="alice", is_admin=False)
        )

        assert response.assessment_id == str(assessment.id)
        with pytest.raises(AssessmentNotFoundError):
            assessments.get(assessment.id)
