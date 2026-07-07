"""Integration: DI wiring with the bootstrap container + full use-case slice."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from kingsec.application import (
    AssessmentRepository,
    CreateAssessment,
    CreateAssessmentRequest,
    GenerateReport,
    GenerateReportRequest,
    GetAssessment,
    GetAssessmentRequest,
    RenderedReport,
    ReportRepository,
    StartAssessment,
    StartAssessmentRequest,
)
from kingsec.application.ports import ReportGeneratorPort, ScannerPort
from kingsec.bootstrap import Container
from kingsec.domain import Finding, Report, Severity, Target
from kingsec.infrastructure.config import Settings
from kingsec.infrastructure.persistence import (
    SqlAlchemyAssessmentRepository,
    SqlAlchemyReportRepository,
    create_database_engine,
    register_persistence,
)


class _StubScanner(ScannerPort):
    def scan(self, target: Target) -> Sequence[Finding]:
        return [Finding.create("SQLi", "injectable", Severity.CRITICAL)]


class _StubReportGenerator(ReportGeneratorPort):
    def render(self, report: Report) -> RenderedReport:
        return RenderedReport(b"%PDF fake", "application/pdf", f"{report.assessment_id}.pdf")


class TestContainerWiring:
    def test_register_persistence_binds_ports(self, tmp_path: Path) -> None:
        container = Container()
        engine = create_database_engine(url=f"sqlite:///{tmp_path / 'k.db'}")

        register_persistence(container, Settings(), engine=engine)

        # Ports resolve to the SQLite adapters.
        assert isinstance(
            container.resolve(AssessmentRepository), SqlAlchemyAssessmentRepository
        )
        assert isinstance(
            container.resolve(ReportRepository), SqlAlchemyReportRepository
        )

    def test_shutdown_hook_disposes_engine(self, tmp_path: Path) -> None:
        container = Container()
        engine = create_database_engine(url=f"sqlite:///{tmp_path / 'k.db'}")
        register_persistence(container, Settings(), engine=engine)

        # Running shutdown hooks should dispose the engine's pool without error.
        container.run_shutdown_hooks()


class TestEndToEndSlice:
    """The four use cases (Module 3.2) running on the real SQLite adapters."""

    def test_full_vertical_slice(self, tmp_path: Path) -> None:
        container = Container()
        engine = create_database_engine(url=f"sqlite:///{tmp_path / 'k.db'}")
        register_persistence(container, Settings(), engine=engine)

        assessments = container.resolve(AssessmentRepository)
        reports = container.resolve(ReportRepository)

        # 1. Create (persisted, AUTHORIZED)
        created = CreateAssessment(assessments).execute(
            CreateAssessmentRequest("10.0.0.5", "ip_address", "tester", "10.0.0.5")
        )

        # 2. Start (loads from DB, scans, records, completes, re-saves)
        started = StartAssessment(assessments, _StubScanner()).execute(
            StartAssessmentRequest(created.assessment_id)
        )
        assert started.status == "completed"
        assert started.findings_count == 1

        # 3. Get (loads persisted state)
        view = GetAssessment(assessments).execute(
            GetAssessmentRequest(created.assessment_id)
        )
        assert view.status == "completed"
        assert len(view.findings) == 1

        # 4. Generate report (persists snapshot, renders)
        report = GenerateReport(assessments, reports, _StubReportGenerator()).execute(
            GenerateReportRequest(created.assessment_id)
        )
        assert report.highest_severity == Severity.CRITICAL.label
        assert report.artifact_media_type == "application/pdf"

        # The report snapshot is durable and reloadable.
        from kingsec.domain import AssessmentId

        reloaded = reports.get(AssessmentId(created.assessment_id))
        assert reloaded.total_findings == 1

        container.run_shutdown_hooks()
