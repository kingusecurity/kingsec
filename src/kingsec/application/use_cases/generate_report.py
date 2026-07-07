"""Use case: generate a report for a completed assessment.

Steps: load the assessment, build the immutable domain ``Report`` snapshot (the
domain enforces that the assessment must be COMPLETED), persist the snapshot,
render a deliverable artifact via the ``ReportGeneratorPort``, and return a
conclusions-first summary DTO.
"""

from __future__ import annotations

from kingsec.domain import Report

from .._support import to_assessment_id
from ..dto import GenerateReportRequest, GenerateReportResponse, SeverityCount
from ..ports import AssessmentRepository, ReportGeneratorPort, ReportRepository


class GenerateReport:
    """Produce, persist, and render a report for a completed assessment."""

    def __init__(
        self,
        assessments: AssessmentRepository,
        reports: ReportRepository,
        generator: ReportGeneratorPort,
    ) -> None:
        self._assessments = assessments
        self._reports = reports
        self._generator = generator

    def execute(self, request: GenerateReportRequest) -> GenerateReportResponse:
        assessment = self._assessments.get(to_assessment_id(request.assessment_id))

        # Report.from_assessment raises IllegalStateTransition if the assessment
        # is not COMPLETED — a domain rule we let propagate.
        report = Report.from_assessment(assessment)

        self._reports.save(report)
        rendered = self._generator.render(report)

        highest = report.verdict.highest_severity
        return GenerateReportResponse(
            assessment_id=report.assessment_id,
            verdict=report.verdict.headline,
            action_required=report.verdict.action_required,
            highest_severity=highest.label if highest is not None else None,
            total_findings=report.total_findings,
            severity_counts=tuple(
                SeverityCount(severity.label, count)
                for severity, count in report.severity_counts
            ),
            artifact_media_type=rendered.media_type,
            artifact_filename=rendered.filename,
            artifact_bytes=len(rendered.content),
        )
