"""Use case: cancel an assessment.

Cancels a not-yet-terminal assessment. The domain FSM enforces which states
allow cancellation (DRAFT, AUTHORIZED, RUNNING). Terminal states (COMPLETED,
CANCELLED, FAILED) raise IllegalStateTransition.

When the assessment is RUNNING, cancelling must also stop the actual scan
work: the use case signals the ``AssessmentExecutionEngine``, whose
cancellation event the scanner orchestrator and the subprocess runner
observe. Flipping the domain state alone is what made cancellation a
no-op in production (HTTP 200 while scanners kept running) — the engine
signal is what gives the 200 its meaning.
"""

from __future__ import annotations

import logging

from kingsec.application._support import check_assessment_access, to_assessment_id
from kingsec.application.assessment_execution import AssessmentExecutionEngine
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
        execution_engine: AssessmentExecutionEngine | None = None,
    ) -> None:
        self._assessments = assessments
        self._events = events
        self._audit = audit
        self._execution_engine = execution_engine

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

        # Stop the actual scan work, not just the domain state. The engine
        # sets its per-assessment cancellation event, which the
        # orchestrator (between scanners, during retry cooldowns) and the
        # subprocess runner (mid-scan, killing the process tree) observe.
        # Without this, cancel was a 200-OK no-op: the background thread
        # kept scanning and later overwrote CANCELLED with its own
        # terminal state.
        if self._execution_engine is not None:
            self._execution_engine.cancel_execution(str(assessment.id))

        self._publish_event(
            AssessmentEvent(
                event_type=EVENT_ASSESSMENT_CANCELLED,
                assessment_id=str(assessment.id),
                state=assessment.status.value,
                message="Assessment cancelled",
                owner_id=assessment.owner_id,
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
