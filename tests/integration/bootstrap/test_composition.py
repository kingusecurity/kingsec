"""Integration tests for the Module 5.4 composition root."""

from __future__ import annotations

import ast
import io
import pathlib
from collections.abc import Sequence

import httpx
import pytest
import sqlalchemy

from kingsec.application import (
    AIPort,
    AssessmentRepository,
    CreateAssessment,
    CreateAssessmentRequest,
    GenerateReport,
    GenerateReportRequest,
    GetAssessment,
    GetAssessmentRequest,
    ReportGeneratorPort,
    ReportRepository,
    ScannerPort,
    StartAssessment,
    StartAssessmentRequest,
    UnitOfWorkFactory,
)
from kingsec.bootstrap import Application
from kingsec.bootstrap.composition import create_wired_application
from kingsec.domain import Finding, Severity, Target

from kingsec.infrastructure.persistence import (
    create_database_engine,
    create_schema,
)

_SRC = pathlib.Path(__file__).resolve().parents[3] / "src" / "kingsec"


@pytest.fixture
def wired_app(tmp_path, monkeypatch) -> Application:
    # Point persistence at a temp DB and keep logs out of the console.
    monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(tmp_path))
    # Create the schema so the app can operate without Alembic migrations.
    engine = create_database_engine(url=f"sqlite:///{tmp_path / 'kingsec.db'}")
    create_schema(engine)
    engine.dispose()
    return create_wired_application(
        log_stream=io.StringIO(),
        ensure_directories=False,
        validate_migrations=False,
    )


class _StubScanner(ScannerPort):
    """Stands in for the real Nuclei adapter (no nuclei binary in CI)."""

    def scan(self, target: Target) -> Sequence[Finding]:
        return [Finding.create("SQLi", "injectable", Severity.CRITICAL)]


class TestStartup:
    def test_complete_application_startup(self, wired_app: Application) -> None:
        with wired_app as app:
            assert app.settings is not None
            assert app.logger is not None

    def test_every_port_resolves(self, wired_app: Application) -> None:
        with wired_app as app:
            from kingsec.infrastructure.ai import AIProviderAdapter
            from kingsec.infrastructure.persistence import (
                SqlAlchemyAssessmentRepository,
                SqlAlchemyReportRepository,
                SqlAlchemyUnitOfWorkFactory,
            )
            from kingsec.infrastructure.reporting import ReportGeneratorAdapter
            from kingsec.infrastructure.scanner import NucleiScannerAdapter

            assert isinstance(app.resolve(AssessmentRepository), SqlAlchemyAssessmentRepository)
            assert isinstance(app.resolve(ReportRepository), SqlAlchemyReportRepository)
            assert isinstance(app.resolve(UnitOfWorkFactory), SqlAlchemyUnitOfWorkFactory)
            assert isinstance(app.resolve(ScannerPort), NucleiScannerAdapter)
            assert isinstance(app.resolve(AIPort), AIProviderAdapter)
            assert isinstance(app.resolve(ReportGeneratorPort), ReportGeneratorAdapter)

    def test_use_cases_resolve_from_di(self, wired_app: Application) -> None:
        with wired_app as app:
            assert isinstance(app.resolve(CreateAssessment), CreateAssessment)
            assert isinstance(app.resolve(StartAssessment), StartAssessment)
            assert isinstance(app.resolve(GetAssessment), GetAssessment)
            assert isinstance(app.resolve(GenerateReport), GenerateReport)


class TestDependencyGraph:
    def test_full_flow_through_wired_graph(self, wired_app: Application) -> None:
        with wired_app as app:
            # Override only the scanner (no nuclei binary available); everything
            # else is the real wired adapter (real SQLite, real PDF renderer).
            app.container.register_instance(ScannerPort, _StubScanner())

            created = app.resolve(CreateAssessment).execute(
                CreateAssessmentRequest("10.0.0.5", "ip_address", "tester", "10.0.0.5")
            )
            # AI has no key configured -> enrichment fails safe (best-effort).
            started = app.resolve(StartAssessment).execute(
                StartAssessmentRequest(created.assessment_id)
            )
            assert started.status == "completed"
            assert started.findings_count == 1

            view = app.resolve(GetAssessment).execute(
                GetAssessmentRequest(created.assessment_id)
            )
            assert view.status == "completed"

            report = app.resolve(GenerateReport).execute(
                GenerateReportRequest(created.assessment_id)
            )
            assert report.artifact_media_type == "application/pdf"
            assert report.artifact_bytes > 1000

    def test_unit_of_work_factory_produces_working_uow(self, wired_app: Application) -> None:
        with wired_app as app:
            factory = app.resolve(UnitOfWorkFactory)
            with factory() as uow:
                assert uow.assessments is not None
                assert uow.reports is not None


class TestShutdown:
    def test_shutdown_disposes_engine_and_http_client(self, tmp_path, monkeypatch) -> None:
        disposed = {"engine": 0, "http": 0}
        real_dispose = sqlalchemy.Engine.dispose
        real_close = httpx.Client.close

        def spy_dispose(self):
            disposed["engine"] += 1
            return real_dispose(self)

        def spy_close(self):
            disposed["http"] += 1
            return real_close(self)

        # Patch BEFORE composition so the wired engine/client are the spied ones.
        monkeypatch.setattr(sqlalchemy.Engine, "dispose", spy_dispose)
        monkeypatch.setattr(httpx.Client, "close", spy_close)
        monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(tmp_path))

        # Create the schema so the app can operate without Alembic migrations.
        engine = create_database_engine(url=f"sqlite:///{tmp_path / 'kingsec.db'}")
        create_schema(engine)
        engine.dispose()

        app = create_wired_application(
            log_stream=io.StringIO(),
            ensure_directories=False,
            validate_migrations=False,
        )
        app.start()
        app.stop()

        assert disposed["engine"] >= 1  # engine.dispose ran on shutdown
        assert disposed["http"] >= 1    # http client closed on shutdown


class TestArchitecture:
    def test_infrastructure_never_imports_bootstrap(self) -> None:
        # The real invariant: dependencies point inward; the composition root
        # (bootstrap) knows concretes, but infrastructure must not depend on it.
        offenders: list[str] = []
        for path in (_SRC / "infrastructure").rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                if any(n.startswith("kingsec.bootstrap") for n in names):
                    offenders.append(path.name)
        assert offenders == []

    def test_application_never_imports_infrastructure(self) -> None:
        offenders: list[str] = []
        for path in (_SRC / "application").rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                if any(n.startswith("kingsec.infrastructure") for n in names):
                    offenders.append(path.name)
        assert offenders == []

    def test_no_circular_dependencies(self) -> None:
        # If any layer had an import cycle, importing these would raise. Importing
        # the composition root exercises the whole graph in one shot.
        import importlib

        for module in (
            "kingsec.domain",
            "kingsec.application",
            "kingsec.infrastructure.persistence",
            "kingsec.infrastructure.scanner",
            "kingsec.infrastructure.ai",
            "kingsec.infrastructure.reporting",
            "kingsec.bootstrap.composition",
        ):
            assert importlib.import_module(module) is not None
