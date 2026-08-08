"""Use case: create a new assessment.

Design note — authorization is captured at creation. KingSec is trust-first: you
should never hold an assessment you weren't authorized to run. So this use case
records the ``Authorization`` immediately, leaving the assessment in the
AUTHORIZED state (ready to start). A separate "authorize later" flow could be
added as its own use case if the product ever needs a draft-then-approve step.
"""

from __future__ import annotations

import logging

from kingsec.application._support import build_target
from kingsec.application.dto import CreateAssessmentRequest, CreateAssessmentResponse
from kingsec.application.events import EVENT_ASSESSMENT_CREATED, AssessmentEvent
from kingsec.application.ports import AssessmentRepository, AuditPublisher, EventPublisher
from kingsec.domain import Assessment, Authorization
from kingsec.domain.audit import AuditAction, AuditEntry


class CreateAssessment:
    """Create, authorize, and persist a new assessment."""

    def __init__(
        self,
        assessments: AssessmentRepository,
        events: EventPublisher | None = None,
        audit: AuditPublisher | None = None,
    ) -> None:
        # Constructor injection: the use case depends on the ABSTRACT port, not a
        # concrete repository. The composition root supplies the real one.
        self._assessments = assessments
        self._events = events
        self._audit = audit

    def execute(self, request: CreateAssessmentRequest) -> CreateAssessmentResponse:
        # Translate raw primitives into a validated domain Target (raises
        # InputValidationError on bad input).
        target = build_target(request.target_value, request.target_type)

        assessment = Assessment.create(target, profile_id=request.profile_id)
        if request.owner_id:
            assessment.set_ownership(request.owner_id)
        authorization = Authorization.grant(request.authorized_by, request.scope)
        assessment.authorize(authorization)

        self._assessments.save(assessment)

        self._publish_event(
            AssessmentEvent(
                event_type=EVENT_ASSESSMENT_CREATED,
                assessment_id=str(assessment.id),
                state=assessment.status.value,
                message=f"Assessment created for {assessment.target}",
            )
        )

        self._publish_audit(
            AuditEntry(
                action=AuditAction.ASSESSMENT_CREATED,
                resource_type="assessment",
                resource_id=str(assessment.id),
                success=True,
                metadata={"target": str(assessment.target), "authorized_by": request.authorized_by},
            )
        )

        return CreateAssessmentResponse(
            assessment_id=str(assessment.id),
            status=assessment.status.value,
            target=str(assessment.target),
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
