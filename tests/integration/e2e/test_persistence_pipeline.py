from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from kingsec.application import AssessmentNotFoundError
from kingsec.application.jobs import IllegalJobTransitionError, JobStatus
from kingsec.application.ports.repositories import Asset
from kingsec.application.unit_of_work import UnitOfWorkPort
from kingsec.bootstrap.production import (
    ProductionApplication,
    ProductionReportService,
    create_production_application,
)
from kingsec.domain import (
    Assessment,
    AssessmentId,
    Authorization,
    Finding,
    ScannerId,
    ScannerResult,
    Severity,
    Target,
    TargetType,
)
from kingsec.domain.report import Report
from kingsec.infrastructure.config import Settings
from kingsec.infrastructure.config.models import StorageSettings
from kingsec.infrastructure.persistence import (
    create_database_engine,
    create_schema,
    create_session_factory,
)
from kingsec.infrastructure.persistence.repositories import (
    SQLAlchemyAssessmentRepository,
    SQLAlchemyAssetRepository,
    SQLAlchemyJobRepository,
    SQLAlchemyReportRepository,
    SQLAlchemyScanRepository,
)
from kingsec.infrastructure.persistence.unit_of_work import SQLAlchemyUnitOfWork


# ===========================================================================
# Helpers — domain object factories
# ===========================================================================


def make_assessment() -> Assessment:
    a = Assessment(AssessmentId.generate(), Target("example.com", TargetType.HOSTNAME))
    a.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=timezone.utc), scope="*"))
    a.start()
    a.record_finding(Finding.create("Vuln A", "desc", Severity.CRITICAL))
    a.complete()
    return a


def make_scan_result() -> ScannerResult:
    return ScannerResult(
        scanner_id=ScannerId("nmap"),
        findings=(Finding.create("Port 443", "TLS issue", Severity.HIGH),),
        raw_output="nmap output",
        duration_seconds=3.0,
    )


def make_asset() -> Asset:
    return Asset(
        id="asset-001",
        target=Target("10.0.0.1", TargetType.IP_ADDRESS),
        discovered_at=datetime.now(timezone.utc),
    )


def make_report(assessment: Assessment) -> Report:
    return Report.from_assessment(assessment)


# ===========================================================================
# Fixtures — file-based SQLite for persistence across sessions
# ===========================================================================


@pytest.fixture
def db_path() -> Path:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        return Path(f.name)


@pytest.fixture
def db_url(db_path: Path) -> str:
    return f"sqlite:///{db_path}"


@pytest.fixture
def settings(db_path: Path) -> Settings:
    return Settings(storage=StorageSettings(data_dir=db_path.parent))


@pytest.fixture
def engine(db_url: str) -> Engine:
    eng = create_database_engine(url=db_url)
    create_schema(eng)
    return eng


@pytest.fixture
def session(engine: Engine) -> Session:
    s = Session(engine)
    try:
        yield s
    finally:
        s.close()


@pytest.fixture
def uow(session: Session) -> SQLAlchemyUnitOfWork:
    return SQLAlchemyUnitOfWork(session)


@pytest.fixture
def fresh_session(engine: Engine) -> Session:
    s = Session(engine)
    try:
        yield s
    finally:
        s.close()


@pytest.fixture
def fresh_uow(fresh_session: Session) -> SQLAlchemyUnitOfWork:
    return SQLAlchemyUnitOfWork(fresh_session)


@pytest.fixture
def app(db_url: str) -> ProductionApplication:
    return create_production_application(
        settings=Settings(
            storage=StorageSettings(
                data_dir=Path(tempfile.mkdtemp()),
            ),
        ),
    )


@pytest.fixture
def api_client(app: ProductionApplication) -> TestClient:
    return TestClient(app.fastapi_app)


# ===========================================================================
# 1. Application boot
# ===========================================================================


class TestApplicationBoot:
    def test_production_application_boots(self, app: ProductionApplication) -> None:
        assert isinstance(app, ProductionApplication)

    def test_database_initializes(self, app: ProductionApplication) -> None:
        assert isinstance(app.engine, Engine)
        import sqlalchemy
        with app.engine.connect() as conn:
            tables = sqlalchemy.inspect(app.engine).get_table_names()
        assert "assessments" in tables
        assert "scan_results" in tables
        assert "scan_jobs" in tables
        assert "assets" in tables
        assert "scan_reports" in tables

    def test_api_starts(self, app: ProductionApplication) -> None:
        assert isinstance(app.fastapi_app, FastAPI)

    def test_api_health(self, api_client: TestClient) -> None:
        resp = api_client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "healthy"}


# ===========================================================================
# 2. Persistence — each entity survives round-trip
# ===========================================================================


class TestAssessmentPersistence:
    def test_assessment_persists(self, session: Session) -> None:
        repo = SQLAlchemyAssessmentRepository(session)
        assessment = make_assessment()
        repo.save(assessment)
        session.commit()
        loaded = repo.get(assessment.id)
        assert loaded.id == assessment.id
        assert loaded.status.name == "COMPLETED"

    def test_assessment_retrieved_not_found(self, session: Session) -> None:
        repo = SQLAlchemyAssessmentRepository(session)
        with pytest.raises(AssessmentNotFoundError):
            repo.get(AssessmentId("no-such-id"))


class TestScanPersistence:
    def test_scan_persists(self, session: Session) -> None:
        repo = SQLAlchemyScanRepository(session)
        result = make_scan_result()
        repo.save("scan-001", result)
        session.commit()
        loaded = repo.get("scan-001")
        assert loaded.scanner_id.value == "nmap"
        assert len(loaded.findings) == 1

    def test_scan_exists(self, session: Session) -> None:
        repo = SQLAlchemyScanRepository(session)
        repo.save("scan-002", make_scan_result())
        session.commit()
        assert repo.exists("scan-002") is True
        assert repo.exists("no-such") is False


class TestReportPersistence:
    def test_report_persists(self, session: Session) -> None:
        repo = SQLAlchemyReportRepository(session)
        assessment = make_assessment()
        report = make_report(assessment)
        repo.save(report)
        session.commit()
        loaded = repo.get(AssessmentId(assessment.id.value))
        assert loaded.assessment_id == report.assessment_id
        assert len(loaded.entries) == 1


class TestJobPersistence:
    def test_job_persists(self, uow: SQLAlchemyUnitOfWork) -> None:
        from kingsec.application.jobs import JobId, ScanJob
        job_id = JobId("job-e2e-001")
        now = datetime.now(timezone.utc)
        job = ScanJob(id=job_id, target="e2e-test.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now)
        with uow:
            uow.job_repository.save(job)
            uow.commit()
        with uow:
            loaded = uow.job_repository.get("job-e2e-001")
            assert loaded.target == "e2e-test.com"

    def test_job_list(self, uow: SQLAlchemyUnitOfWork) -> None:
        from kingsec.application.jobs import JobId, ScanJob
        now = datetime.now(timezone.utc)
        jobs = [
            ScanJob(id=JobId(f"job-e2e-{i}"), target=f"t{i}.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now)
            for i in range(3)
        ]
        with uow:
            for job in jobs:
                uow.job_repository.save(job)
            uow.commit()
        with uow:
            lst = uow.job_repository.list()
            assert len(lst) == 3


class TestAssetPersistence:
    def test_asset_persists(self, session: Session) -> None:
        repo = SQLAlchemyAssetRepository(session)
        asset = make_asset()
        repo.add(asset)
        session.commit()
        loaded = repo.get("asset-001")
        assert loaded.id == "asset-001"
        assert loaded.target.value == "10.0.0.1"

    def test_asset_list(self, session: Session) -> None:
        repo = SQLAlchemyAssetRepository(session)
        for i in range(3):
            a = Asset(id=f"asset-{i:03d}", target=Target(f"10.0.0.{i}", TargetType.IP_ADDRESS), discovered_at=datetime.now(timezone.utc))
            repo.add(a)
        session.commit()
        lst = repo.list()
        assert len(lst) == 3


# ===========================================================================
# 3. Unit of Work — commit persists, rollback discards
# ===========================================================================


class TestUnitOfWorkCommit:
    def test_commit_persists(self, session: Session) -> None:
        uow = SQLAlchemyUnitOfWork(session)
        from kingsec.application.jobs import JobId, ScanJob
        now = datetime.now(timezone.utc)
        job = ScanJob(id=JobId("uow-commit-1"), target="commit-test.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now)
        with uow:
            uow.job_repository.save(job)
            uow.commit()
        repo = SQLAlchemyJobRepository(session)
        loaded = repo.get("uow-commit-1")
        assert loaded.target == "commit-test.com"


class TestUnitOfWorkRollback:
    def test_rollback_discards(self, session: Session) -> None:
        uow = SQLAlchemyUnitOfWork(session)
        from kingsec.application.jobs import JobId, ScanJob
        now = datetime.now(timezone.utc)
        job = ScanJob(id=JobId("uow-rollback-1"), target="rollback-test.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now)
        with uow:
            uow.job_repository.save(job)
            uow.rollback()
        repo = SQLAlchemyJobRepository(session)
        with pytest.raises(Exception):
            repo.get("uow-rollback-1")


# ===========================================================================
# 4. Cross-session — data visible after new session
# ===========================================================================


class TestCrossSessionPersistence:
    def test_data_visible_after_new_session(self, engine: Engine) -> None:
        session1 = Session(engine)
        uow1 = SQLAlchemyUnitOfWork(session1)
        from kingsec.application.jobs import JobId, ScanJob
        now = datetime.now(timezone.utc)
        job = ScanJob(id=JobId("xsession-001"), target="xsession.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now)
        with uow1:
            uow1.job_repository.save(job)
            uow1.commit()
        session1.close()

        session2 = Session(engine)
        uow2 = SQLAlchemyUnitOfWork(session2)
        with uow2:
            loaded = uow2.job_repository.get("xsession-001")
            assert loaded.target == "xsession.com"
        session2.close()

    def test_multi_entity_persistence_across_sessions(self, engine: Engine) -> None:
        session_a = Session(engine)
        uow_a = SQLAlchemyUnitOfWork(session_a)
        with uow_a:
            assessment = make_assessment()
            uow_a.assessment_repository.save(assessment)
            uow_a.commit()
        session_a.close()

        session_b = Session(engine)
        uow_b = SQLAlchemyUnitOfWork(session_b)
        with uow_b:
            loaded = uow_b.assessment_repository.get(assessment.id)
            assert loaded.target.value == "example.com"
        session_b.close()


# ===========================================================================
# 5. API Integration — jobs endpoints
# ===========================================================================


class TestApiJobs:
    def test_create_job_returns_202(self, api_client: TestClient) -> None:
        resp = api_client.post("/jobs", json={"target": "api-test.com"})
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "PENDING"
        assert data["target"] == "api-test.com"

    def test_create_job_returns_job_id(self, api_client: TestClient) -> None:
        resp = api_client.post("/jobs", json={"target": "api-test.com"})
        assert resp.status_code == 202
        assert "job_id" in resp.json()

    def test_retrieve_job(self, api_client: TestClient) -> None:
        created = api_client.post("/jobs", json={"target": "get-test.com"}).json()
        job_id = created["job_id"]
        resp = api_client.get(f"/jobs/{job_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["target"] == "get-test.com"
        assert data["status"] == "PENDING"

    def test_cancel_job(self, api_client: TestClient) -> None:
        created = api_client.post("/jobs", json={"target": "cancel-test.com"}).json()
        job_id = created["job_id"]
        resp = api_client.delete(f"/jobs/{job_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "CANCELLED"

    def test_list_jobs(self, api_client: TestClient) -> None:
        api_client.post("/jobs", json={"target": "list-1.com"})
        api_client.post("/jobs", json={"target": "list-2.com"})
        resp = api_client.get("/jobs")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 2

    def test_get_unknown_job_returns_404(self, api_client: TestClient) -> None:
        resp = api_client.get("/jobs/no-such-job")
        assert resp.status_code == 404

    def test_cancel_unknown_job_returns_404(self, api_client: TestClient) -> None:
        resp = api_client.delete("/jobs/no-such-job")
        assert resp.status_code == 404

    def test_job_result_for_non_completed_returns_409(self, api_client: TestClient) -> None:
        created = api_client.post("/jobs", json={"target": "result-test.com"}).json()
        job_id = created["job_id"]
        resp = api_client.get(f"/jobs/{job_id}/result")
        assert resp.status_code == 409


# ===========================================================================
# 6. Report Flow — generate, retrieve, download
# ===========================================================================


class TestReportFlow:
    def test_generate_report(self, api_client: TestClient) -> None:
        resp = api_client.post("/report", json={"scan_id": "scan-001"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert "report_id" in data

    def test_retrieve_report(self, api_client: TestClient) -> None:
        generated = api_client.post("/report", json={"scan_id": "scan-002"}).json()
        report_id = generated["report_id"]
        resp = api_client.get(f"/report/{report_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["report_id"] == report_id

    def test_download_markdown(self, api_client: TestClient) -> None:
        generated = api_client.post("/report", json={"scan_id": "scan-003"}).json()
        report_id = generated["report_id"]
        resp = api_client.get(f"/report/{report_id}/download/markdown")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/markdown")

    def test_download_html(self, api_client: TestClient) -> None:
        generated = api_client.post("/report", json={"scan_id": "scan-004"}).json()
        report_id = generated["report_id"]
        resp = api_client.get(f"/report/{report_id}/download/html")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/html")

    def test_download_pdf(self, api_client: TestClient) -> None:
        generated = api_client.post("/report", json={"scan_id": "scan-005"}).json()
        report_id = generated["report_id"]
        resp = api_client.get(f"/report/{report_id}/download/pdf")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"

    def test_download_json(self, api_client: TestClient) -> None:
        generated = api_client.post("/report", json={"scan_id": "scan-006"}).json()
        report_id = generated["report_id"]
        resp = api_client.get(f"/report/{report_id}/download/json")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/json"

    def test_download_csv(self, api_client: TestClient) -> None:
        generated = api_client.post("/report", json={"scan_id": "scan-007"}).json()
        report_id = generated["report_id"]
        resp = api_client.get(f"/report/{report_id}/download/csv")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")

    def test_download_sarif(self, api_client: TestClient) -> None:
        generated = api_client.post("/report", json={"scan_id": "scan-008"}).json()
        report_id = generated["report_id"]
        resp = api_client.get(f"/report/{report_id}/download/sarif")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/sarif+json"

    def test_get_report_summary(self, api_client: TestClient) -> None:
        generated = api_client.post("/report", json={"scan_id": "scan-009"}).json()
        report_id = generated["report_id"]
        resp = api_client.get(f"/report/{report_id}/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "executive_summary" in data
        assert "risk_summary" in data

    def test_get_report_formats(self, api_client: TestClient) -> None:
        generated = api_client.post("/report", json={"scan_id": "scan-010"}).json()
        report_id = generated["report_id"]
        resp = api_client.get(f"/report/{report_id}/formats")
        assert resp.status_code == 200
        formats = resp.json()
        assert "markdown" in formats
        assert "html" in formats
        assert "pdf" in formats
        assert "json" in formats
        assert "csv" in formats
        assert "sarif" in formats

    def test_download_unknown_format_returns_404(self, api_client: TestClient) -> None:
        generated = api_client.post("/report", json={"scan_id": "scan-011"}).json()
        report_id = generated["report_id"]
        resp = api_client.get(f"/report/{report_id}/download/unknown")
        assert resp.status_code == 404

    def test_get_unknown_report_returns_404(self, api_client: TestClient) -> None:
        resp = api_client.get("/report/no-such-report")
        assert resp.status_code == 404


# ===========================================================================
# 7. Atomicity — multi-repository commit / rollback
# ===========================================================================


class TestAtomicity:
    def test_multi_repo_commit(self, session: Session) -> None:
        uow = SQLAlchemyUnitOfWork(session)
        from kingsec.application.jobs import JobId, ScanJob
        now = datetime.now(timezone.utc)
        with uow:
            assessment = make_assessment()
            uow.assessment_repository.save(assessment)
            job = ScanJob(id=JobId("atomic-job-001"), target="atomic.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now)
            uow.job_repository.save(job)
            uow.commit()
        repo_assessment = SQLAlchemyAssessmentRepository(session)
        repo_job = SQLAlchemyJobRepository(session)
        loaded_assessment = repo_assessment.get(assessment.id)
        assert loaded_assessment.target.value == "example.com"
        loaded_job = repo_job.get("atomic-job-001")
        assert loaded_job.target == "atomic.com"

    def test_rollback_removes_all_pending_writes(self, session: Session) -> None:
        uow = SQLAlchemyUnitOfWork(session)
        from kingsec.application.jobs import JobId, ScanJob
        now = datetime.now(timezone.utc)
        with uow:
            assessment = make_assessment()
            uow.assessment_repository.save(assessment)
            job = ScanJob(id=JobId("atomic-rollback-001"), target="rollback-atomic.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now)
            uow.job_repository.save(job)
            uow.rollback()
        repo_assessment = SQLAlchemyAssessmentRepository(session)
        repo_job = SQLAlchemyJobRepository(session)
        with pytest.raises(AssessmentNotFoundError):
            repo_assessment.get(assessment.id)
        with pytest.raises(Exception):
            repo_job.get("atomic-rollback-001")

    def test_context_manager_rollback_on_exception(self, session: Session) -> None:
        uow = SQLAlchemyUnitOfWork(session)
        from kingsec.application.jobs import JobId, ScanJob
        now = datetime.now(timezone.utc)
        with pytest.raises(ValueError):
            with uow:
                uow.job_repository.save(
                    ScanJob(id=JobId("ctx-exc-001"), target="ctx-test.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now)
                )
                raise ValueError("simulated failure")
        repo = SQLAlchemyJobRepository(session)
        assert repo.exists("ctx-exc-001") is False

    def test_uncommitted_context_manager_auto_rollback(self, session: Session) -> None:
        uow = SQLAlchemyUnitOfWork(session)
        from kingsec.application.jobs import JobId, ScanJob
        now = datetime.now(timezone.utc)
        with uow:
            uow.job_repository.save(
                ScanJob(id=JobId("uncommitted-001"), target="uncommitted.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now)
            )
        repo = SQLAlchemyJobRepository(session)
        assert repo.exists("uncommitted-001") is False


# ===========================================================================
# 8. Failure Recovery — transaction failure leaves database consistent
# ===========================================================================


class TestFailureRecovery:
    def test_failed_transaction_leaves_db_consistent(self, session: Session) -> None:
        uow = SQLAlchemyUnitOfWork(session)
        from kingsec.application.jobs import JobId, ScanJob
        now = datetime.now(timezone.utc)

        assessment = make_assessment()
        with uow:
            uow.assessment_repository.save(assessment)
            uow.commit()

        session.close()
        session2 = Session(session.get_bind())
        uow2 = SQLAlchemyUnitOfWork(session2)
        with uow2:
            uow2.assessment_repository.save(assessment)
            uow2.commit()
        session2.close()

        session3 = Session(session.get_bind())
        repo3 = SQLAlchemyAssessmentRepository(session3)
        loaded = repo3.get(assessment.id)
        assert loaded.target.value == "example.com"
        session3.close()

    def test_isolated_transactions_dont_interfere(self, session: Session) -> None:
        from kingsec.application.jobs import JobId, ScanJob
        uow1 = SQLAlchemyUnitOfWork(session)
        now = datetime.now(timezone.utc)
        with uow1:
            uow1.job_repository.save(
                ScanJob(id=JobId("isolated-001"), target="first.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now)
            )
            uow1.commit()

        uow2 = SQLAlchemyUnitOfWork(session)
        with uow2:
            uow2.job_repository.save(
                ScanJob(id=JobId("isolated-002"), target="second.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now)
            )
            uow2.commit()

        repo = SQLAlchemyJobRepository(session)
        assert repo.get("isolated-001").target == "first.com"
        assert repo.get("isolated-002").target == "second.com"

    def test_error_during_commit_does_not_corrupt_existing_data(self, session: Session) -> None:
        from kingsec.application.jobs import JobId, ScanJob
        now = datetime.now(timezone.utc)
        repo = SQLAlchemyJobRepository(session)
        repo.save(ScanJob(id=JobId("pre-existing"), target="stable.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now))
        session.commit()

        uow = SQLAlchemyUnitOfWork(session)
        with uow:
            uow.job_repository.save(
                ScanJob(id=JobId("during-error"), target="unstable.com", config={}, status=JobStatus.PENDING, created_at=now, updated_at=now)
            )
            uow.rollback()

        loaded = repo.get("pre-existing")
        assert loaded.target == "stable.com"


# ===========================================================================
# 9. Bootstrap — dependencies wired correctly
# ===========================================================================


class TestBootstrapWiring:
    def test_all_dependencies_wired(self, app: ProductionApplication) -> None:
        assert app.engine is not None
        assert app.session_factory is not None
        assert app.uow is not None
        assert app.assessment_repository is not None
        assert app.report_repository is not None
        assert app.scan_repository is not None
        assert app.job_repository is not None
        assert app.asset_repository is not None
        assert app.job_service is not None
        assert app.scanner_registry is not None
        assert app.scanner_orchestrator is not None
        assert app.report_service is not None
        assert app.fastapi_app is not None

    def test_no_duplicate_instances(self, app: ProductionApplication) -> None:
        repos = [
            app.assessment_repository,
            app.report_repository,
            app.scan_repository,
            app.job_repository,
            app.asset_repository,
        ]
        assert len({id(r) for r in repos}) == 5

    def test_same_unit_of_work_shared(self, app: ProductionApplication) -> None:
        assert app.uow.assessment_repository is not None
        assert app.uow.report_repository is not None
        assert app.uow.scan_repository is not None
        assert app.uow.job_repository is not None
        assert app.uow.asset_repository is not None

    def test_job_service_is_persistent(self, app: ProductionApplication) -> None:
        from kingsec.application.services.persistent_job_service import PersistentJobService
        assert isinstance(app.job_service, PersistentJobService)

    def test_report_service_is_production(self, app: ProductionApplication) -> None:
        assert isinstance(app.report_service, ProductionReportService)

    def test_session_factory_creates_sessions(self, app: ProductionApplication) -> None:
        sess = app.session_factory()
        assert isinstance(sess, Session)
        sess.close()

    def test_all_renderers_wired(self, app: ProductionApplication) -> None:
        assert app.markdown_renderer is not None
        assert app.html_renderer is not None
        assert app.pdf_renderer is not None
        assert app.json_renderer is not None
        assert app.csv_renderer is not None
        assert app.sarif_renderer is not None
        assert app.report_builder is not None
        assert app.executive_summary_generator is not None

    def test_command_runner_wired(self, app: ProductionApplication) -> None:
        assert app.command_runner is not None

    def test_scanner_registry_has_plugins(self, app: ProductionApplication) -> None:
        plugins = app.scanner_registry.list_all()
        assert len(plugins) > 0

    def test_all_api_routes_registered(self, app: ProductionApplication) -> None:
        openapi = app.fastapi_app.openapi()
        paths = list(openapi.get("paths", {}).keys())
        prefixes = ["/jobs", "/scan", "/report", "/health", "/version"]
        for prefix in prefixes:
            assert any(prefix in p for p in paths), f"Missing route for {prefix}"


# ===========================================================================
# 10. Architecture Verification — Clean Architecture preserved
# ===========================================================================


class TestArchitecture:
    def test_api_layer_does_not_import_infrastructure(self) -> None:
        import kingsec.interfaces.api.app as api_app
        src = api_app.__file__
        assert src is not None
        with open(src) as f:
            content = f.read()
        assert "SQLAlchemy" not in content
        assert "sqlalchemy" not in content.lower()

    def test_api_routes_only_use_ports(self) -> None:
        import kingsec.interfaces.api.routes.jobs as jobs_route
        with open(jobs_route.__file__) as f:
            content = f.read()
        assert "JobServicePort" in content
        assert "SQLAlchemy" not in content

    def test_persistent_job_service_no_sqlalchemy(self) -> None:
        import kingsec.application.services.persistent_job_service as pjs
        with open(pjs.__file__) as f:
            content = f.read()
        assert "from sqlalchemy" not in content
        assert "import sqlalchemy" not in content

    def test_repositories_unchanged(self) -> None:
        import kingsec.infrastructure.persistence.repositories.assessment as arepo
        assert hasattr(arepo, "SQLAlchemyAssessmentRepository")

    def test_unit_of_work_port_unchanged(self) -> None:
        from kingsec.application.unit_of_work import UnitOfWorkPort
        assert hasattr(UnitOfWorkPort, "begin")
        assert hasattr(UnitOfWorkPort, "commit")
        assert hasattr(UnitOfWorkPort, "rollback")
        assert hasattr(UnitOfWorkPort, "close")

    def test_bootstrap_only_composition_root_instantiates_infrastructure(self) -> None:
        import kingsec.bootstrap.production as prod
        with open(prod.__file__) as f:
            content = f.read()
        assert "PersistentJobService" in content
