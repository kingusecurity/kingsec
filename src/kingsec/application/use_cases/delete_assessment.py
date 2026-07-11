"""Use case: delete an assessment.

Removes an assessment and all its children (findings, evidence,
recommendations) from the database. The cascade delete is handled by the
persistence layer (ON DELETE CASCADE on foreign keys).

If the assessment does not exist, AssessmentNotFoundError is raised.
The domain is not involved — deletion is a repository concern.
"""

from __future__ import annotations

from .._support import to_assessment_id
from ..dto import DeleteAssessmentRequest, DeleteAssessmentResponse
from ..ports import AssessmentRepository


class DeleteAssessment:
    """Delete an assessment and all its children."""

    def __init__(self, assessments: AssessmentRepository) -> None:
        self._assessments = assessments

    def execute(self, request: DeleteAssessmentRequest) -> DeleteAssessmentResponse:
        assessment_id = to_assessment_id(request.assessment_id)

        # Verify existence before delete (raises AssessmentNotFoundError if missing).
        self._assessments.get(assessment_id)

        # Delete the assessment and all children via cascade.
        self._assessments.delete(assessment_id)

        return DeleteAssessmentResponse(assessment_id=request.assessment_id)
