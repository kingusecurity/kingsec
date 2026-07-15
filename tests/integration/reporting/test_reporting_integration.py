"""Reporting integration tests: real PDF/HTML + full assessment→report slice."""

from __future__ import annotations

import io
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

import pytest

from kingsec.application import (
    CreateAssessment,
    CreateAssessmentRequest,
    GenerateReport,
    GenerateReportRequest,
    ReportGeneratorPort,
    ScannerPort,
    StartAssessment,
    StartAssessmentRequest,
)
from kingsec.bootstrap import Container
from kingsec.domain import (
    Assessment,
    Authorization,
    Finding,
    Report,
    Severity,
    Target,
    TargetType,
)
from kingsec.infrastructure.config.models import LoggingSettings
from kingsec.infrastructure.logging import configure_logging
from kingsec.infrastructure.persistence import (
    SqlAlchemyAssessmentRepository,
    SqlAlchemyReportRepository,
    create_database_engine,
    create_schema,
    create_session_factory,
)
from kingsec.infrastructure.reporting import (
    ReportGeneratorAdapter,
    register_reporting,
)

configure_logging(LoggingSettings(level="ERROR", json_format=True), stream=io.StringIO())


def _weasyprint_available() -> bool:
    """Return True only if WeasyPrint can actually render PDFs."""
    try:
        from weasyprint import HTML
        HTML(string="<p>test</p>").write_pdf()
        return True
    except Exception:  # noqa: BLE001
        return False


needs_weasyprint = pytest.mark.skipif(
    not _weasyprint_available(),
    reason="WeasyPrint native dependencies (GTK/Pango) are not available",
)


def _report() -> Report:
    a = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    a.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=timezone.utc), scope="s"))
    a.start()
    a.record_finding(Finding.create("SQLi", "x", Severity.CRITICAL))
    a.complete()
    return Report.from_assessment(a)


class _StubScanner(ScannerPort):
    def scan(self, target: Target) -> Sequence[Finding]:
        return [Finding.create("SQLi", "injectable", Severity.CRITICAL)]


class TestRealRendering:
    @needs_weasyprint
    def test_real_pdf_generation(self) -> None:
        result = ReportGeneratorAdapter(output_format="pdf").render(_report())
        assert result.media_type == "application/pdf"
        assert result.content.startswith(b"%PDF-")
        assert len(result.content) > 1000  # a real, non-trivial document

    def test_real_html_generation(self) -> None:
        result = ReportGeneratorAdapter(output_format="html").render(_report())
        assert result.content.startswith(b"<!DOCTYPE html>")
        assert b"Executive Summary" in result.content


class TestDependencyInjection:
    @needs_weasyprint
    def test_registered_port_generates_pdf(self) -> None:
        container = Container()
        register_reporting(container, output_format="pdf", brand_name="AcmeSec")
        port = container.resolve(ReportGeneratorPort)
        result = port.render(_report())
        assert result.content.startswith(b"%PDF-")


class TestFullSlice:
    @needs_weasyprint
    def test_assessment_to_report(self, tmp_path: Path) -> None:
        engine = create_database_engine(url=f"sqlite:///{tmp_path / 'k.db'}")
        create_schema(engine)
        sf = create_session_factory(engine)
        assessments = SqlAlchemyAssessmentRepository(sf)
        reports = SqlAlchemyReportRepository(sf)
        generator = ReportGeneratorAdapter(output_format="pdf")

        try:
            created = CreateAssessment(assessments).execute(
                CreateAssessmentRequest("10.0.0.5", "ip_address", "tester", "10.0.0.5")
            )
            StartAssessment(assessments, _StubScanner()).execute(
                StartAssessmentRequest(created.assessment_id)
            )
            response = GenerateReport(assessments, reports, generator).execute(
                GenerateReportRequest(created.assessment_id)
            )

            # The use case rendered a real PDF deliverable through this adapter.
            assert response.artifact_media_type == "application/pdf"
            assert response.artifact_filename.endswith(".pdf")
            assert response.artifact_bytes > 1000
            # And the report snapshot is persisted.
            from kingsec.domain import AssessmentId

            stored = reports.get(AssessmentId(created.assessment_id))
            assert stored.total_findings == 1
        finally:
            engine.dispose()
