"""Use case: submit an assessment for background execution.

This is the async counterpart of ``StartAssessment``. Instead of running the
scan synchronously, it transitions the assessment to RUNNING and submits the
scan work to a ``JobRunner`` for background execution. The caller receives
immediate confirmation (HTTP 202) while the scan runs in a background thread.

The application layer does not know about threads, executors, or asyncio.
It submits a callable to the ``JobRunner`` port; the infrastructure decides
how to execute it.

Error handling
    If the background scan fails, the assessment is marked FAILED with a
    reason. The caller can poll ``GET /assessments/{id}`` to see the final
    state.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from kingsec.domain import AssessmentId, Finding
from kingsec.domain.audit import AuditAction, AuditEntry

from ._support import check_assessment_access, to_assessment_id
from .assessment_execution import AssessmentExecutionEngine, ExecutionPhase
from .dto import SubmitAssessmentRequest, SubmitAssessmentResponse
from .events import (
    EVENT_ASSESSMENT_COMPLETED,
    EVENT_ASSESSMENT_FAILED,
    EVENT_ASSESSMENT_RUNNING,
    AssessmentEvent,
)
from .ports import (
    AIPort,
    AssessmentRepository,
    AuditPublisher,
    EventPublisher,
    JobRunner,
    ScannerPort,
)


class SubmitAssessment:
    """Validate an assessment and submit it for background scanning."""

    def __init__(
        self,
        assessments: AssessmentRepository,
        scanner: ScannerPort,
        job_runner: JobRunner,
        ai: AIPort | None = None,
        events: EventPublisher | None = None,
        audit: AuditPublisher | None = None,
        execution_engine: AssessmentExecutionEngine | None = None,
    ) -> None:
        self._assessments = assessments
        self._scanner = scanner
        self._job_runner = job_runner
        self._ai = ai
        self._events = events
        self._audit = audit
        self._execution_engine = execution_engine

    def execute(self, request: SubmitAssessmentRequest) -> SubmitAssessmentResponse:
        assessment_id = to_assessment_id(request.assessment_id)
        assessment = self._assessments.get(assessment_id)
        check_assessment_access(assessment, request.requesting_user, request.is_admin)

        # The authorization gate: AUTHORIZED -> RUNNING.
        # Raises IllegalStateTransition if not authorized.
        assessment.start()
        self._assessments.save(assessment)

        self._publish_event(
            AssessmentEvent(
                event_type=EVENT_ASSESSMENT_RUNNING,
                assessment_id=str(assessment.id),
                state=assessment.status.value,
                message="Background scan started",
            )
        )

        self._publish_audit(
            AuditEntry(
                action=AuditAction.ASSESSMENT_SUBMITTED,
                resource_type="assessment",
                resource_id=str(assessment.id),
                success=True,
            )
        )

        # Submit background work. The closure captures the ports it needs.
        job_id = str(assessment.id)
        background_fn = self._make_background_fn(
            assessment_id=assessment_id,
            assessments=self._assessments,
            scanner=self._scanner,
            ai=self._ai,
            events=self._events,
            execution_engine=self._execution_engine,
        )
        self._job_runner.submit(job_id, background_fn)

        return SubmitAssessmentResponse(
            assessment_id=str(assessment.id),
            status=assessment.status.value,
            job_id=job_id,
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

    @staticmethod
    def _make_background_fn(
        *,
        assessment_id: AssessmentId,
        assessments: AssessmentRepository,
        scanner: ScannerPort,
        ai: AIPort | None,
        events: EventPublisher | None,
        execution_engine: AssessmentExecutionEngine | None,
    ) -> Callable[[], None]:
        """Build a closure that runs the scan in the background."""

        def _run_scan() -> None:
            _execute_scan(
                assessment_id=assessment_id,
                assessments=assessments,
                scanner=scanner,
                ai=ai,
                events=events,
                execution_engine=execution_engine,
            )

        return _run_scan


def _execute_scan(
    *,
    assessment_id: AssessmentId,
    assessments: AssessmentRepository,
    scanner: ScannerPort,
    ai: AIPort | None,
    events: EventPublisher | None = None,
    execution_engine: AssessmentExecutionEngine | None = None,
) -> None:
    """Run the scan and complete the assessment. Called from a background thread.

    Each call gets a fresh assessment object from the repository so there is
    no shared mutable state between threads.
    """
    assessment = assessments.get(assessment_id)
    tracking_id = str(assessment_id)

    if execution_engine is not None:
        execution_engine.start_execution(tracking_id, {})
        execution_engine.transition_phase(tracking_id, ExecutionPhase.RUNNING_SCANNERS)

    try:
        for finding in scanner.scan(assessment.target):
            _enrich(finding, ai)
            assessment.record_finding(finding)

        if execution_engine is not None:
            execution_engine.transition_phase(tracking_id, ExecutionPhase.CORRELATING)
            execution_engine.transition_phase(tracking_id, ExecutionPhase.REPORTING)

        assessment.complete()
        assessments.save(assessment)

        if execution_engine is not None:
            execution_engine.transition_phase(tracking_id, ExecutionPhase.COMPLETED)

        _publish_event(
            events,
            AssessmentEvent(
                event_type=EVENT_ASSESSMENT_COMPLETED,
                assessment_id=str(assessment.id),
                state=assessment.status.value,
                message=f"Scan completed with {len(assessment.findings)} findings",
                severity_counts=_severity_counts(assessment),
            ),
        )

    except Exception as exc:
        if execution_engine is not None:
            execution_engine.fail_execution(tracking_id, str(exc))
        try:
            assessment.fail(str(exc))
            assessments.save(assessment)

            _publish_event(
                events,
                AssessmentEvent(
                    event_type=EVENT_ASSESSMENT_FAILED,
                    assessment_id=str(assessment.id),
                    state=assessment.status.value,
                    message=f"Scan failed: {exc}",
                ),
            )
        except Exception as exc:
            logging.getLogger(__name__).warning("scan recovery failed (best-effort): %s", exc)


def _enrich(finding: Finding, ai: AIPort | None) -> None:
    """Attach an AI recommendation if available (best-effort)."""
    if ai is None:
        return
    try:
        recommendation = ai.recommend(finding)
        finding.add_recommendation(recommendation)
    except Exception as exc:
        logging.getLogger(__name__).warning("AI enrichment failed (best-effort): %s", exc)
        return


def _publish_event(events: EventPublisher | None, event: AssessmentEvent) -> None:
    """Publish an event if a publisher is configured (best-effort)."""
    if events is None:
        return
    try:
        events.publish(event)
    except Exception as exc:
        logging.getLogger(__name__).warning("event publish failed (best-effort): %s", exc)


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
