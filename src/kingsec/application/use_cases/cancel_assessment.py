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

import logging

from kingsec.application._support import check_assessment_access, to_assessment_id
from kingsec.application.dto import CancelAssessmentRequest, CancelAssessmentResponse
from kingsec.application.events import EVENT_ASSESSMENT_CANCELLED, AssessmentEvent
from kingsec.application.ports import AssessmentRepository, AuditPublisher, EventPublisher
from kingsec.domain.audit import AuditAction, AuditEntry


class CancelAssessment:
    """Cancel a not-yet-terminal assessment."""

    def __init__(
        self,
        assessments: AssessmentRepository,
        events: EventPublisher | None = None,
        audit: AuditPublisher | None = None,
    ) -> None:
        self._assessments = assessments
        self._events = events
        self._audit = audit

    def execute(self, request: CancelAssessmentRequest) -> CancelAssessmentResponse:
        assessment = self._assessments.get(to_assessment_id(request.assessment_id))
        check_assessment_access(assessment, request.requesting_user, request.is_admin)

        # The domain FSM enforces the cancellation gate:
        # - DRAFT -> CANCELLED
        # - AUTHORIZED -> CANCELLED
        # - RUNNING -> CANCELLED
        # - COMPLETED/CANCELLED/FAILED -> IllegalStateTransition
        assessment.cancel()
        self._assessments.save(assessment)

        self._publish_event(
            AssessmentEvent(
                event_type=EVENT_ASSESSMENT_CANCELLED,
                assessment_id=str(assessment.id),
                state=assessment.status.value,
                message="Assessment cancelled",
            )
        )

        self._publish_audit(
            AuditEntry(
                action=AuditAction.ASSESSMENT_CANCELLED,
                resource_type="assessment",
                resource_id=str(assessment.id),
                success=True,
                user_id=request.requesting_user,
                username=request.requesting_username,
            )
        )

        return CancelAssessmentResponse(
            assessment_id=str(assessment.id),
            status=assessment.status.value,
        )

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
