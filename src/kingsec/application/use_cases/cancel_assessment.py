"""Use case: cancel an assessment.

Cancels a not-yet-terminal assessment. The domain FSM enforces which states
allow cancellation (DRAFT, AUTHORIZED, RUNNING). Terminal states (COMPLETED,
CANCELLED, FAILED) raise IllegalStateTransition.

If the assessment is RUNNING when cancelled, the background job should
ideally be stopped. However, this use case does not own job lifecycle —
it transitions the domain state. A future module can add job cancellation
by querying the JobRunner port.
"""

from __future__ import annotations

from .._support import to_assessment_id
from ..dto import CancelAssessmentRequest, CancelAssessmentResponse
from ..ports import AssessmentRepository


class CancelAssessment:
    """Cancel a not-yet-terminal assessment."""

    def __init__(self, assessments: AssessmentRepository) -> None:
        self._assessments = assessments

    def execute(self, request: CancelAssessmentRequest) -> CancelAssessmentResponse:
        assessment = self._assessments.get(to_assessment_id(request.assessment_id))

        # The domain FSM enforces the cancellation gate:
        # - DRAFT -> CANCELLED
        # - AUTHORIZED -> CANCELLED
        # - RUNNING -> CANCELLED
        # - COMPLETED/CANCELLED/FAILED -> IllegalStateTransition
        assessment.cancel()
        self._assessments.save(assessment)

        return CancelAssessmentResponse(
            assessment_id=str(assessment.id),
            status=assessment.status.value,
        )
