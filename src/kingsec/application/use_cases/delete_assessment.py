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
from ..events import AssessmentEvent, EVENT_ASSESSMENT_DELETED
from ..ports import AssessmentRepository, EventPublisher


class DeleteAssessment:
    """Delete an assessment and all its children."""

    def __init__(
        self,
        assessments: AssessmentRepository,
        events: EventPublisher | None = None,
    ) -> None:
        self._assessments = assessments
        self._events = events

    def execute(self, request: DeleteAssessmentRequest) -> DeleteAssessmentResponse:
        assessment_id = to_assessment_id(request.assessment_id)

        # Verify existence before delete (raises AssessmentNotFoundError if missing).
        self._assessments.get(assessment_id)

        # Delete the assessment and all children via cascade.
        self._assessments.delete(assessment_id)

        self._publish(
            AssessmentEvent(
                event_type=EVENT_ASSESSMENT_DELETED,
                assessment_id=request.assessment_id,
                state="deleted",
                message="Assessment deleted",
            )
        )

        return DeleteAssessmentResponse(assessment_id=request.assessment_id)

    def _publish(self, event: AssessmentEvent) -> None:
        """Publish an event if a publisher is configured (best-effort)."""
        if self._events is None:
            return
        try:
            self._events.publish(event)
        except Exception:  # noqa: BLE001 - event publishing is best-effort
            pass
