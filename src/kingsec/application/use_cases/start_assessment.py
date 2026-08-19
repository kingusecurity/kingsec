"""Use case: start (run) an assessment.

Orchestrates a full run synchronously: transition to RUNNING (which enforces the
authorization gate in the domain), scan the target, enrich each finding with an
optional AI recommendation, record the findings, and complete.

Why synchronous here? The application layer models *what* happens. Real execution
will be asynchronous with progress milestones — but that scheduling/streaming is
an infrastructure concern, layered on top of this use case later, not baked into
the business logic.

AI enrichment is best-effort by design (bring-your-own-key, optional): a provider
failure must never fail an authorized scan, so enrichment errors are swallowed.
Observability for those failures is added at the adapter, which can log them.
"""

from __future__ import annotations

import logging

from kingsec.application._support import safe_failure_message, to_assessment_id
from kingsec.application.assessment_profiles import ExecutionPlanner
from kingsec.application.dto import StartAssessmentRequest, StartAssessmentResponse
from kingsec.application.errors import ExecutionPlanUnsatisfiedError
from kingsec.application.events import (
    EVENT_ASSESSMENT_COMPLETED,
    EVENT_ASSESSMENT_FAILED,
    EVENT_ASSESSMENT_RUNNING,
    AssessmentEvent,
)
from kingsec.application.ports import (
    AIPort,
    AssessmentRepository,
    AuditPublisher,
    EventPublisher,
    ScannerPort,
)
from kingsec.domain import Finding
from kingsec.domain.audit import AuditAction, AuditEntry


class StartAssessment:
    """Run an authorized assessment to completion."""

    def __init__(
        self,
        assessments: AssessmentRepository,
        scanner: ScannerPort,
        ai: AIPort | None = None,
        events: EventPublisher | None = None,
        audit: AuditPublisher | None = None,
        planner: ExecutionPlanner | None = None,
    ) -> None:
        self._assessments = assessments
        self._scanner = scanner
        self._ai = ai  # optional: AI enrichment is not required to run a scan
        self._events = events
        self._audit = audit
        self._planner = planner

    def execute(self, request: StartAssessmentRequest) -> StartAssessmentResponse:
        assessment = self._assessments.get(to_assessment_id(request.assessment_id))

        # The authorization gate lives in the domain: this raises
        # IllegalStateTransition if the assessment was never authorized. We let
        # that domain error propagate — it is a precise, meaningful signal.
        assessment.start()
        self._assessments.save(assessment)

        self._publish_event(
            AssessmentEvent(
                event_type=EVENT_ASSESSMENT_RUNNING,
                assessment_id=str(assessment.id),
                state=assessment.status.value,
                message="Scan started",
            )
        )

        self._publish_audit(
            AuditEntry(
                action=AuditAction.ASSESSMENT_STARTED,
                resource_type="assessment",
                resource_id=str(assessment.id),
                success=True,
            )
        )

        try:
            scanner_ids: tuple[str, ...] | None = None
            if assessment.profile_id is not None and self._planner is not None:
                # Server-side re-validation: re-plan now, at run time, rather
                # than trusting whatever the client saw at an earlier /plan
                # preview - scanner availability can change in the gap.
                plan = self._planner.plan(assessment.profile_id, assessment.target.value, assessment.target.type)
                if not plan.can_proceed:
                    reason = "; ".join(plan.warnings) or (
                        f"profile {assessment.profile_id!r} cannot proceed: "
                        "a required scanner is unavailable"
                    )
                    raise ExecutionPlanUnsatisfiedError(reason)
                scanner_ids = tuple(e.scanner_id for e in plan.selected_scanners)

            scan_results = (
                self._scanner.scan(assessment.target, scanner_ids=scanner_ids)
                if scanner_ids is not None
                else self._scanner.scan(assessment.target)
            )
            for finding in scan_results:
                self._enrich(finding)
                assessment.record_finding(finding)

            assessment.complete()
            self._assessments.save(assessment)

            self._publish_event(
                AssessmentEvent(
                    event_type=EVENT_ASSESSMENT_COMPLETED,
                    assessment_id=str(assessment.id),
                    state=assessment.status.value,
                    message=f"Scan completed with {len(assessment.findings)} findings",
                    severity_counts=self._severity_counts(assessment),
                )
            )

            self._publish_audit(
                AuditEntry(
                    action=AuditAction.ASSESSMENT_COMPLETED,
                    resource_type="assessment",
                    resource_id=str(assessment.id),
                    success=True,
                    metadata={"findings_count": len(assessment.findings)},
                )
            )

            highest = assessment.highest_severity
            return StartAssessmentResponse(
                assessment_id=str(assessment.id),
                status=assessment.status.value,
                findings_count=len(assessment.findings),
                highest_severity=highest.label if highest is not None else None,
            )

        except Exception as exc:
            # Best-effort failure recording.
            try:
                assessment.fail(safe_failure_message(exc))
                self._assessments.save(assessment)

                self._publish_event(
                    AssessmentEvent(
                        event_type=EVENT_ASSESSMENT_FAILED,
                        assessment_id=str(assessment.id),
                        state=assessment.status.value,
                        message=f"Scan failed: {exc}",
                    )
                )

                self._publish_audit(
                    AuditEntry(
                        action=AuditAction.ASSESSMENT_FAILED,
                        resource_type="assessment",
                        resource_id=str(assessment.id),
                        success=False,
                        reason=str(exc),
                    )
                )
            except Exception as exc:
                logging.getLogger(__name__).warning("recovery audit failed (best-effort): %s", exc)
            raise

    def _enrich(self, finding: Finding) -> None:
        """Attach an AI recommendation if an AI port is configured (best-effort)."""
        if self._ai is None:
            return
        try:
            recommendation = self._ai.recommend(finding)
            finding.add_recommendation(recommendation)
        except Exception:
            # Intentionally swallowed: an AI outage must not fail an authorized
            # scan. The adapter is responsible for logging the underlying error.
            return

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

    @staticmethod
    def _severity_counts(assessment: object) -> dict[str, int] | None:
        """Build a severity count dict from the assessment's findings."""
        from kingsec.domain import Assessment as AssessmentType

        if not isinstance(assessment, AssessmentType):
            return None
        counts: dict[str, int] = {}
        for finding in assessment.findings:
            label = finding.severity.label
            counts[label] = counts.get(label, 0) + 1
        return counts if counts else None
