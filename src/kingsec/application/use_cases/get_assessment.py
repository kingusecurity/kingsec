"""Use case: fetch a single assessment as a boundary-safe view."""

from __future__ import annotations

from .._support import to_assessment_id
from ..dto import AssessmentView, GetAssessmentRequest
from ..ports import AssessmentRepository


class GetAssessment:
    """Retrieve an assessment and present it as a DTO (no domain object leaks)."""

    def __init__(self, assessments: AssessmentRepository) -> None:
        self._assessments = assessments

    def execute(self, request: GetAssessmentRequest) -> AssessmentView:
        # repo.get raises AssessmentNotFoundError if the id is unknown.
        assessment = self._assessments.get(to_assessment_id(request.assessment_id))
        return AssessmentView.from_domain(assessment)
