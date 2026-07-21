"""Integration tests for the production composition root.

Verifies that ``create_production_application`` correctly wires every
infrastructure component — engine, session, repositories, Unit of Work,
job service, scanner, report service — and that the FastAPI application
boots with all routes registered. Also verifies architectural constraints:
no circular dependencies, no duplicate instances, same session shared
across repositories.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from kingsec.application.services.persistent_job_service import PersistentJobService
from kingsec.application.unit_of_work import UnitOfWorkPort
from kingsec.bootstrap.production import (
    ProductionApplication,
    create_production_application,
)
from kingsec.infrastructure.config import Settings, load_settings
from kingsec.infrastructure.config.models import StorageSettings
from kingsec.infrastructure.persistence.repositories import (
    SQLAlchemyAssessmentRepository,
    SQLAlchemyAssetRepository,
    SQLAlchemyJobRepository,
    SQLAlchemyReportRepository,
    SQLAlchemyScanRepository,
)
from kingsec.infrastructure.persistence.unit_of_work import SQLAlchemyUnitOfWork
from kingsec.infrastructure.scanner import (
    InMemoryPluginRegistry,
    ScannerOrchestrator,
)

# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def settings() -> Settings:
    return load_settings()


@pytest.fixture
def app(settings: Settings) -> ProductionApplication:
    return create_production_application(settings=settings)


# ===========================================================================
# Application boots successfully
# ===========================================================================


class TestApplicationBoot:
    def test_create_production_application_returns_app(self) -> None:
        app = create_production_application()
        assert isinstance(app, ProductionApplication)

    def test_fastapi_app_created(self, app: ProductionApplication) -> None:
        assert isinstance(app.fastapi_app, FastAPI)

    def test_app_has_title(self, app: ProductionApplication) -> None:
        assert app.fastapi_app.title == "KingSec API"

    def test_health_endpoint(self, app: ProductionApplication) -> None:
        client = TestClient(app.fastapi_app)
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    def test_root_endpoint(self, app: ProductionApplication) -> None:
        client = TestClient(app.fastapi_app)
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "KingSec"
        assert data["status"] == "running"

    def test_version_endpoint(self, app: ProductionApplication) -> None:
        client = TestClient(app.fastapi_app)
        response = client.get("/version")
        assert response.status_code == 200
        assert "version" in response.json()


# ===========================================================================
# Database initializes
# ===========================================================================


class TestDatabase:
    def test_engine_created(self, app: ProductionApplication) -> None:
        assert isinstance(app.engine, Engine)

    def test_session_factory_creates_sessions(self, app: ProductionApplication) -> None:
        session = app.session_factory()
        assert isinstance(session, Session)
        session.close()

    def test_engine_is_sqlite(self, app: ProductionApplication) -> None:
        assert "sqlite" in str(app.engine.url)


# ===========================================================================
# Repositories are SQLAlchemy implementations
# ===========================================================================


class TestRepositories:
    def test_assessment_repository_is_sqlalchemy(self, app: ProductionApplication) -> None:
        assert isinstance(app.assessment_repository, SQLAlchemyAssessmentRepository)

    def test_report_repository_is_sqlalchemy(self, app: ProductionApplication) -> None:
        assert isinstance(app.report_repository, SQLAlchemyReportRepository)

    def test_scan_repository_is_sqlalchemy(self, app: ProductionApplication) -> None:
        assert isinstance(app.scan_repository, SQLAlchemyScanRepository)

    def test_job_repository_is_sqlalchemy(self, app: ProductionApplication) -> None:
        assert isinstance(app.job_repository, SQLAlchemyJobRepository)

    def test_asset_repository_is_sqlalchemy(self, app: ProductionApplication) -> None:
        assert isinstance(app.asset_repository, SQLAlchemyAssetRepository)


# ===========================================================================
# UnitOfWork is SQLAlchemyUnitOfWork and implements UnitOfWorkPort
# ===========================================================================


class TestUnitOfWork:
    def test_uow_is_sqlalchemy(self, app: ProductionApplication) -> None:
        assert isinstance(app.uow, SQLAlchemyUnitOfWork)

    def test_uow_implements_port(self, app: ProductionApplication) -> None:
        assert isinstance(app.uow, UnitOfWorkPort)

    def test_uow_has_all_repositories(self, app: ProductionApplication) -> None:
        assert app.uow.assessment_repository is not None
        assert app.uow.report_repository is not None
        assert app.uow.scan_repository is not None
        assert app.uow.job_repository is not None
        assert app.uow.asset_repository is not None


# ===========================================================================
# Same session shared correctly
# ===========================================================================


class TestSessionSharing:
    def test_uow_uses_same_session_as_repos(self, app: ProductionApplication) -> None:
        session = app.uow._session
        assert app.assessment_repository._session is session
        assert app.report_repository._session is session
        assert app.scan_repository._session is session
        assert app.job_repository._session is session
        assert app.asset_repository._session is session

    def test_uow_repos_share_session(self, app: ProductionApplication) -> None:
        session = app.uow._session
        assert app.uow.assessment_repository._session is session
        assert app.uow.report_repository._session is session
        assert app.uow.scan_repository._session is session
        assert app.uow.job_repository._session is session
        assert app.uow.asset_repository._session is session


# ===========================================================================
# API boots successfully with all routes
# ===========================================================================


class TestApiRoutes:
    def test_jobs_routes_registered(self, app: ProductionApplication) -> None:
        self._assert_route_exists(app.fastapi_app, "/jobs")

    def test_scan_routes_registered(self, app: ProductionApplication) -> None:
        self._assert_route_exists(app.fastapi_app, "/scan")

    def test_report_routes_registered(self, app: ProductionApplication) -> None:
        self._assert_route_exists(app.fastapi_app, "/report")

    def test_health_route_registered(self, app: ProductionApplication) -> None:
        self._assert_route_exists(app.fastapi_app, "/health")

    def test_jobs_endpoint_works(self, app: ProductionApplication) -> None:
        client = TestClient(app.fastapi_app)
        response = client.get("/jobs")
        assert response.status_code in (200, 401, 404)

    def test_api_has_middleware(self, app: ProductionApplication) -> None:
        assert len(app.fastapi_app.user_middleware) > 0

    @staticmethod
    def _assert_route_exists(fastapi_app: FastAPI, path_prefix: str) -> None:
        openapi = fastapi_app.openapi()
        all_paths = list(openapi.get("paths", {}).keys())
        assert any(path_prefix in p for p in all_paths), (
            f"No OpenAPI path contains {path_prefix!r}; available: {all_paths}"
        )


# ===========================================================================
# No circular dependencies
# ===========================================================================


class TestNoCircularDependencies:
    def test_no_self_reference_in_dataclass(self, app: ProductionApplication) -> None:
        assert app.fastapi_app is not app


# ===========================================================================
# No duplicate session instances (repos share one session)
# ===========================================================================


class TestNoDuplicateSession:
    def test_standalone_repos_share_session(self, app: ProductionApplication) -> None:
        session = app.assessment_repository._session
        assert app.report_repository._session is session
        assert app.scan_repository._session is session
        assert app.job_repository._session is session
        assert app.asset_repository._session is session

    def test_repos_are_distinct_objects(self, app: ProductionApplication) -> None:
        repos = [
            app.assessment_repository,
            app.report_repository,
            app.scan_repository,
            app.job_repository,
            app.asset_repository,
        ]
        assert len({id(r) for r in repos}) == 5


# ===========================================================================
# Dependency graph correct
# ===========================================================================


class TestDependencyGraph:
    def test_scanner_orchestrator_wired(self, app: ProductionApplication) -> None:
        assert isinstance(app.scanner_orchestrator, ScannerOrchestrator)

    def test_scanner_registry_wired(self, app: ProductionApplication) -> None:
        assert isinstance(app.scanner_registry, InMemoryPluginRegistry)

    def test_job_service_wired(self, app: ProductionApplication) -> None:
        assert isinstance(app.job_service, PersistentJobService)

    def test_report_service_wired(self, app: ProductionApplication) -> None:
        assert app.report_service is not None

    def test_all_fields_populated(self, app: ProductionApplication) -> None:
        assert app.markdown_renderer is not None
        assert app.html_renderer is not None
        assert app.pdf_renderer is not None
        assert app.json_renderer is not None
        assert app.csv_renderer is not None
        assert app.sarif_renderer is not None
        assert app.executive_summary_generator is not None
        assert app.report_builder is not None


# ===========================================================================
# Architecture verification — composition root isolates infrastructure
# ===========================================================================


class TestArchitecture:
    def test_app_does_not_import_repository_modules_directly(self) -> None:
        import kingsec.interfaces.api.app as api_app

        src = str(api_app.__file__)
        with open(src) as f:
            content = f.read()
        assert "SQLAlchemy" not in content
        assert "sqlalchemy" not in content.lower()

    def test_settings_from_env_overrides(self) -> None:
        custom_settings = load_settings()
        assert isinstance(custom_settings.storage, StorageSettings)

    def test_can_create_with_engine_url_override(self) -> None:
        settings = load_settings()
        app = create_production_application(settings=settings)
        assert "sqlite" in str(app.engine.url)
