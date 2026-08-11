"""Use case: generate a report for a completed assessment.

Steps: load the assessment, build the immutable domain ``Report`` snapshot (the
domain enforces that the assessment must be COMPLETED), persist the snapshot,
render a deliverable artifact via the ``ReportGeneratorPort``, and return a
conclusions-first summary DTO.
"""

from __future__ import annotations

import dataclasses
import logging
from datetime import datetime

from kingsec.application._support import check_assessment_access, to_assessment_id
from kingsec.application.dto import GenerateReportRequest, GenerateReportResponse, SeverityCount
from kingsec.application.events import EVENT_REPORT_READY, AssessmentEvent
from kingsec.application.ports import (
    AIPort,
    AssessmentRepository,
    AuditPublisher,
    EventPublisher,
    ReportGeneratorPort,
    ReportRepository,
)
from kingsec.domain import Finding, HistoryPoint, Report
from kingsec.domain.audit import AuditAction, AuditEntry

_HISTORY_LIMIT = 20


class GenerateReport:
    """Produce, persist, and render a report for a completed assessment."""

    def __init__(
        self,
        assessments: AssessmentRepository,
        reports: ReportRepository,
        generator: ReportGeneratorPort,
        ai: AIPort | None = None,
        events: EventPublisher | None = None,
        audit: AuditPublisher | None = None,
    ) -> None:
        self._assessments = assessments
        self._reports = reports
        self._generator = generator
        self._ai = ai
        self._events = events
        self._audit = audit

    def execute(self, request: GenerateReportRequest) -> GenerateReportResponse:
        assessment = self._assessments.get(to_assessment_id(request.assessment_id))
        check_assessment_access(assessment, request.requesting_user, request.is_admin)

        # Report.from_assessment raises IllegalStateTransition if the assessment
        # is not COMPLETED — a domain rule we let propagate. It never touches AI
        # (that would be a domain -> application/infrastructure layering
        # violation) — enrichment happens here, in the use case, afterward.
        report = Report.from_assessment(assessment)
        report = self._with_ai_explanations(report, assessment.findings)
        report = self._with_history(report, request)

        self._reports.save(report)
        rendered = self._generator.render(report)

        self._publish_event(
            AssessmentEvent(
                event_type=EVENT_REPORT_READY,
                assessment_id=report.assessment_id,
                state="report_ready",
                message=f"Report generated: {rendered.filename}",
            )
        )

        self._publish_audit(
            AuditEntry(
                action=AuditAction.REPORT_GENERATED,
                resource_type="report",
                resource_id=report.assessment_id,
                success=True,
                user_id=request.requesting_user,
                username=request.requesting_username,
                metadata={"filename": rendered.filename},
            )
        )

        highest = report.verdict.highest_severity
        return GenerateReportResponse(
            assessment_id=report.assessment_id,
            verdict=report.verdict.headline,
            action_required=report.verdict.action_required,
            highest_severity=highest.label if highest is not None else None,
            total_findings=report.total_findings,
            severity_counts=tuple(SeverityCount(severity.label, count) for severity, count in report.severity_counts),
            artifact_media_type=rendered.media_type,
            artifact_filename=rendered.filename,
            artifact_bytes=len(rendered.content),
        )

    def _with_ai_explanations(self, report: Report, findings: tuple[Finding, ...]) -> Report:
        """Best-effort, per-finding AI business-risk explanation.

        Never fails report generation: an AI outage or missing provider
        degrades to ``ai_explanation=None`` on the affected entries, and
        ``report.ai_enabled`` tells the template whether that's because no
        provider was configured at all (mirrors the same best-effort pattern
        already used for scan-time enrichment in ``submit_assessment.py``).
        """
        if self._ai is None:
            return report

        by_id = {str(f.id): f for f in findings}
        new_entries = tuple(
            dataclasses.replace(entry, ai_explanation=self._explain(by_id.get(entry.finding_id)))
            for entry in report.entries
        )
        return dataclasses.replace(report, entries=new_entries, ai_enabled=True)

    def _with_history(self, report: Report, request: GenerateReportRequest) -> Report:
        """Attach prior reports for the same target (risk-over-time chart).

        Queries with the SAME requester identity/permission used for the main
        access check above — never elevated access — so this can never surface
        another user's scan history for the same target. Best-effort: a query
        failure degrades to no history, never fails report generation.

        Excludes this report's own assessment_id from the results: this method
        runs BEFORE self._reports.save(report), so on any generation after the
        first for a given assessment, that assessment's own prior save is
        already sitting in the table and would otherwise be pulled back in as
        if it were a separate historical data point — regenerating a report
        must never inflate its own trend with itself. ReportRepository.list()
        stays a general-purpose query (other callers, e.g. the reports list
        page, correctly want to include this assessment) — "exclude self" is
        specific to building history and belongs here, not in the port.
        """
        try:
            projections, _total = self._reports.list(
                target=report.target,
                order_by="generated_at",
                order_dir="asc",
                limit=_HISTORY_LIMIT,
                requesting_user=request.requesting_user,
                is_admin=request.is_admin,
            )
        except Exception as exc:
            logging.getLogger(__name__).warning("report history lookup failed (best-effort): %s", exc)
            return report

        history = tuple(
            HistoryPoint(
                generated_at=datetime.fromisoformat(p.generated_at),
                executive_score=p.executive_score,
            )
            for p in projections
            if p.assessment_id != report.assessment_id
        )
        return dataclasses.replace(report, history=history)

    def _explain(self, finding: Finding | None) -> str | None:
        """Call the AI port for one finding, or None on any failure (best-effort)."""
        if finding is None or self._ai is None:
            return None
        try:
            return self._ai.explain_business_risk(finding)
        except Exception as exc:
            logging.getLogger(__name__).warning("AI business-risk explanation failed (best-effort): %s", exc)
            return None

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
