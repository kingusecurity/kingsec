"""Use case: fetch a single assessment as a boundary-safe view."""

from __future__ import annotations

from kingsec.application._support import check_assessment_access, to_assessment_id
from kingsec.application.dto import AssessmentView, GetAssessmentRequest
from kingsec.application.ports import AssessmentRepository


class GetAssessment:
    """Retrieve an assessment and present it as a DTO (no domain object leaks)."""

    def __init__(self, assessments: AssessmentRepository) -> None:
        self._assessments = assessments

    def execute(self, request: GetAssessmentRequest) -> AssessmentView:
        # repo.get raises AssessmentNotFoundError if the id is unknown.
        assessment = self._assessments.get(to_assessment_id(request.assessment_id))
        check_assessment_access(assessment, request.requesting_user, request.is_admin)
        return AssessmentView.from_domain(assessment)
