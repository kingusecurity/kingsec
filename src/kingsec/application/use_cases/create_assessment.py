"""Use case: create a new assessment.

Design note — authorization is captured at creation. KingSec is trust-first: you
should never hold an assessment you weren't authorized to run. So this use case
records the ``Authorization`` immediately, leaving the assessment in the
AUTHORIZED state (ready to start). A separate "authorize later" flow could be
added as its own use case if the product ever needs a draft-then-approve step.
"""

from __future__ import annotations

from kingsec.domain import Assessment, Authorization

from .._support import build_target
from ..dto import CreateAssessmentRequest, CreateAssessmentResponse
from ..events import AssessmentEvent, EVENT_ASSESSMENT_CREATED
from ..ports import AssessmentRepository, EventPublisher


class CreateAssessment:
    """Create, authorize, and persist a new assessment."""

    def __init__(
        self,
        assessments: AssessmentRepository,
        events: EventPublisher | None = None,
    ) -> None:
        # Constructor injection: the use case depends on the ABSTRACT port, not a
        # concrete repository. The composition root supplies the real one.
        self._assessments = assessments
        self._events = events

    def execute(self, request: CreateAssessmentRequest) -> CreateAssessmentResponse:
        # Translate raw primitives into a validated domain Target (raises
        # InputValidationError on bad input).
        target = build_target(request.target_value, request.target_type)

        assessment = Assessment.create(target)
        authorization = Authorization.grant(request.authorized_by, request.scope)
        assessment.authorize(authorization)

        self._assessments.save(assessment)

        self._publish(
            AssessmentEvent(
                event_type=EVENT_ASSESSMENT_CREATED,
                assessment_id=str(assessment.id),
                state=assessment.status.value,
                message=f"Assessment created for {assessment.target}",
            )
        )

        return CreateAssessmentResponse(
            assessment_id=str(assessment.id),
            status=assessment.status.value,
            target=str(assessment.target),
        )

    def _publish(self, event: AssessmentEvent) -> None:
        """Publish an event if a publisher is configured (best-effort)."""
        if self._events is None:
            return
        try:
            self._events.publish(event)
        except Exception:  # noqa: BLE001 - event publishing is best-effort
            pass
