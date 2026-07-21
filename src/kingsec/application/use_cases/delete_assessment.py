"""Use case: delete an assessment.

Removes an assessment and all its children (findings, evidence,
recommendations) from the database. The cascade delete is handled by the
persistence layer (ON DELETE CASCADE on foreign keys).

If the assessment does not exist, AssessmentNotFoundError is raised.
The domain is not involved — deletion is a repository concern.
"""

from __future__ import annotations

import logging

from kingsec.application._support import to_assessment_id
from kingsec.application.dto import DeleteAssessmentRequest, DeleteAssessmentResponse
from kingsec.application.events import EVENT_ASSESSMENT_DELETED, AssessmentEvent
from kingsec.application.ports import AssessmentRepository, AuditPublisher, EventPublisher
from kingsec.domain.audit import AuditAction, AuditEntry


class DeleteAssessment:
    """Delete an assessment and all its children."""

    def __init__(
        self,
        assessments: AssessmentRepository,
        events: EventPublisher | None = None,
        audit: AuditPublisher | None = None,
    ) -> None:
        self._assessments = assessments
        self._events = events
        self._audit = audit

    def execute(self, request: DeleteAssessmentRequest) -> DeleteAssessmentResponse:
        assessment_id = to_assessment_id(request.assessment_id)

        # Verify existence before delete (raises AssessmentNotFoundError if missing).
        self._assessments.get(assessment_id)

        # Delete the assessment and all children via cascade.
        self._assessments.delete(assessment_id)

        self._publish_event(
            AssessmentEvent(
                event_type=EVENT_ASSESSMENT_DELETED,
                assessment_id=request.assessment_id,
                state="deleted",
                message="Assessment deleted",
            )
        )

        self._publish_audit(
            AuditEntry(
                action=AuditAction.ASSESSMENT_DELETED,
                resource_type="assessment",
                resource_id=request.assessment_id,
                success=True,
            )
        )

        return DeleteAssessmentResponse(assessment_id=request.assessment_id)

    def _publish_event(self, event: AssessmentEvent) -> None:
        """Publish an event if a publisher is configured (best-effort)."""
        if self._events is None:
            return
        try:
            self._events.publish(event)
        except Exception as exc:
            logging.getLogger(__name__).warning("event publish failed (best-effort): %s", exc)

    def _publish_audit(self, entry: AuditEntry) -> None:
        """Publish an audit entry if a publisher is configured (best-effort)."""
        if self._audit is None:
            return
        try:
            self._audit.record(entry)
        except Exception as exc:
            logging.getLogger(__name__).warning("audit publish failed (best-effort): %s", exc)
