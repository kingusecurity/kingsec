"""Tests for FastAPI routes — unit-level with a stubbed ServiceAPI."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.app import create_fastapi_app
from kingsec.adapters.inbound.web.dependencies import get_service
from kingsec.application.dto import (
    AssessmentView,
    CancelAssessmentRequest,
    CancelAssessmentResponse,
    CreateAssessmentRequest,
    CreateAssessmentResponse,
    FindingView,
    GenerateReportRequest,
    GenerateReportResponse,
    GetAssessmentRequest,
    SeverityCount,
    StartAssessmentRequest,
    StartAssessmentResponse,
    SubmitAssessmentRequest,
    SubmitAssessmentResponse,
)
from kingsec.application.ports.inbound.service_api import ServiceAPI
from kingsec.bootstrap.application import Application
from kingsec.infrastructure.config import Settings


# --- Stub ServiceAPI ---------------------------------------------------------


class StubServiceAPI(ServiceAPI):
    """Returns deterministic responses for route testing."""

    def __init__(self) -> None:
        self.create_called = False
        self.start_called = False
        self.submit_called = False
        self.cancel_called = False
        self.get_called = False
        self.report_called = False

    def create_assessment(
        self, request: CreateAssessmentRequest
    ) -> CreateAssessmentResponse:
        self.create_called = True
        return CreateAssessmentResponse(
            assessment_id="asmt-test-001",
            status="authorized",
            target=f"{request.target_value} ({request.target_type})",
        )

    def start_assessment(
        self, request: StartAssessmentRequest
    ) -> StartAssessmentResponse:
        self.start_called = True
        return StartAssessmentResponse(
            assessment_id=request.assessment_id,
            status="completed",
            findings_count=3,
            highest_severity="critical",
        )

    def submit_assessment(
        self, request: SubmitAssessmentRequest
    ) -> SubmitAssessmentResponse:
        self.submit_called = True
        return SubmitAssessmentResponse(
            assessment_id=request.assessment_id,
            status="running",
            job_id=request.assessment_id,
        )

    def cancel_assessment(
        self, request: CancelAssessmentRequest
    ) -> CancelAssessmentResponse:
        self.cancel_called = True
        return CancelAssessmentResponse(
            assessment_id=request.assessment_id,
            status="cancelled",
        )

    def get_assessment(self, request: GetAssessmentRequest) -> AssessmentView:
        self.get_called = True
        return AssessmentView(
            assessment_id=request.assessment_id,
            target="10.0.0.5 (ip_address)",
            status="completed",
            is_authorized=True,
            created_at="2026-01-01T00:00:00+00:00",
            findings=(
                FindingView(
                    finding_id="find-001",
                    title="SQL Injection",
                    severity="critical",
                    status="open",
                    evidence_count=2,
                    recommendation_count=1,
                ),
            ),
        )

    def generate_report(
        self, request: GenerateReportRequest
    ) -> GenerateReportResponse:
        self.report_called = True
        return GenerateReportResponse(
            assessment_id=request.assessment_id,
            verdict="Needs attention",
            action_required=True,
            highest_severity="critical",
            total_findings=3,
            severity_counts=(
                SeverityCount(severity="critical", count=1),
                SeverityCount(severity="medium", count=2),
            ),
            artifact_media_type="application/pdf",
            artifact_filename="report.pdf",
            artifact_bytes=1024,
        )


# --- Fixtures ----------------------------------------------------------------


@pytest.fixture
def stub_service() -> StubServiceAPI:
    return StubServiceAPI()


@pytest.fixture
def client(stub_service: StubServiceAPI) -> TestClient:
    """Build a TestClient with a minimal Application-like state."""

    app = FastAPI()

    # Minimal stub that has a .resolve() method returning the stub service.
    class _StubApp:
        def resolve(self, service_type: type) -> StubServiceAPI:
            return stub_service

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router

    register_error_handlers(app)
    app.include_router(router)
    app.dependency_overrides[get_service] = lambda: stub_service

    return TestClient(app, raise_server_exceptions=False)


# --- Tests -------------------------------------------------------------------


class TestHealthEndpoint:
    def test_returns_200(self, client: TestClient) -> None:
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestCreateAssessmentEndpoint:
    def test_returns_201(self, client: TestClient, stub_service: StubServiceAPI) -> None:
        resp = client.post(
            "/api/v1/assessments",
            json={
                "target_value": "10.0.0.5",
                "target_type": "ip_address",
                "authorized_by": "admin@co.com",
                "scope": "10.0.0.5",
            },
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["assessment_id"] == "asmt-test-001"
        assert body["status"] == "authorized"
        assert stub_service.create_called

    def test_validation_error_returns_422(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/assessments",
            json={"target_value": ""},
        )
        assert resp.status_code == 422

    def test_empty_body_returns_422(self, client: TestClient) -> None:
        resp = client.post("/api/v1/assessments", json={})
        assert resp.status_code == 422


class TestStartAssessmentEndpoint:
    def test_returns_202(self, client: TestClient, stub_service: StubServiceAPI) -> None:
        resp = client.post("/api/v1/assessments/asmt-001/start")
        assert resp.status_code == 202
        body = resp.json()
        assert body["assessment_id"] == "asmt-001"
        assert body["status"] == "running"
        assert body["job_id"] == "asmt-001"
        assert stub_service.submit_called


class TestCancelAssessmentEndpoint:
    def test_returns_200(self, client: TestClient, stub_service: StubServiceAPI) -> None:
        resp = client.post("/api/v1/assessments/asmt-001/cancel")
        assert resp.status_code == 200
        body = resp.json()
        assert body["assessment_id"] == "asmt-001"
        assert body["status"] == "cancelled"
        assert stub_service.cancel_called


class TestGetAssessmentEndpoint:
    def test_returns_200(self, client: TestClient, stub_service: StubServiceAPI) -> None:
        resp = client.get("/api/v1/assessments/asmt-001")
        assert resp.status_code == 200
        body = resp.json()
        assert body["assessment_id"] == "asmt-001"
        assert body["status"] == "completed"
        assert body["is_authorized"] is True
        assert len(body["findings"]) == 1
        assert body["findings"][0]["title"] == "SQL Injection"
        assert stub_service.get_called


class TestGenerateReportEndpoint:
    def test_returns_200(self, client: TestClient, stub_service: StubServiceAPI) -> None:
        resp = client.post("/api/v1/assessments/asmt-001/report")
        assert resp.status_code == 200
        body = resp.json()
        assert body["assessment_id"] == "asmt-001"
        assert body["verdict"] == "Needs attention"
        assert body["action_required"] is True
        assert body["total_findings"] == 3
        assert len(body["severity_counts"]) == 2
        assert body["artifact_media_type"] == "application/pdf"
        assert body["artifact_bytes"] == 1024
        assert stub_service.report_called


class TestErrorHandling:
    def test_not_found_returns_404(self) -> None:
        """Simulate a ServiceAPI that raises AssessmentNotFoundError."""

        class _FailingService(ServiceAPI):
            def create_assessment(self, r):  # type: ignore[override]
                pass

            def start_assessment(self, r):  # type: ignore[override]
                pass

            def submit_assessment(self, r):  # type: ignore[override]
                pass

            def cancel_assessment(self, r):  # type: ignore[override]
                pass

            def get_assessment(self, r):
                from kingsec.application.errors import AssessmentNotFoundError

                raise AssessmentNotFoundError("asmt-missing")

            def generate_report(self, r):  # type: ignore[override]
                pass

        app = FastAPI()

        class _StubApp:
            def resolve(self, service_type: type) -> _FailingService:
                return _FailingService()

        app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

        from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
        from kingsec.adapters.inbound.web.routes import router

        register_error_handlers(app)
        app.include_router(router)
        app.dependency_overrides[get_service] = lambda: _FailingService()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/assessments/asmt-missing")
        assert resp.status_code == 404
        body = resp.json()
        assert body["error_code"] == "KS-RES-001"

    def test_illegal_state_returns_409(self) -> None:
        """Simulate a ServiceAPI that raises IllegalStateTransition."""

        class _FailingService(ServiceAPI):
            def create_assessment(self, r):  # type: ignore[override]
                pass

            def start_assessment(self, r):
                from kingsec.domain.errors import IllegalStateTransition

                raise IllegalStateTransition(
                    "not authorized", current="draft", attempted="start"
                )

            def submit_assessment(self, r):
                from kingsec.domain.errors import IllegalStateTransition

                raise IllegalStateTransition(
                    "not authorized", current="draft", attempted="start"
                )

            def cancel_assessment(self, r):
                from kingsec.domain.errors import IllegalStateTransition

                raise IllegalStateTransition(
                    "already completed", current="completed", attempted="cancelled"
                )

            def get_assessment(self, r):  # type: ignore[override]
                pass

            def generate_report(self, r):  # type: ignore[override]
                pass

        app = FastAPI()

        class _StubApp:
            def resolve(self, service_type: type) -> _FailingService:
                return _FailingService()

        app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

        from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
        from kingsec.adapters.inbound.web.routes import router

        register_error_handlers(app)
        app.include_router(router)
        app.dependency_overrides[get_service] = lambda: _FailingService()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/assessments/asmt-001/start")
        assert resp.status_code == 409
        body = resp.json()
        assert "not allowed" in body["message"].lower()

    def test_unknown_exception_returns_500(self) -> None:
        """Simulate an unexpected exception — must not leak details."""

        class _FailingService(ServiceAPI):
            def create_assessment(self, r):  # type: ignore[override]
                pass

            def start_assessment(self, r):  # type: ignore[override]
                pass

            def submit_assessment(self, r):  # type: ignore[override]
                pass

            def cancel_assessment(self, r):  # type: ignore[override]
                pass

            def get_assessment(self, r):
                raise RuntimeError("database password is xyz")

            def generate_report(self, r):  # type: ignore[override]
                pass

        app = FastAPI()

        class _StubApp:
            def resolve(self, service_type: type) -> _FailingService:
                return _FailingService()

        app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

        from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
        from kingsec.adapters.inbound.web.routes import router

        register_error_handlers(app)
        app.include_router(router)
        app.dependency_overrides[get_service] = lambda: _FailingService()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/assessments/asmt-001")
        assert resp.status_code == 500
        body = resp.json()
        assert body["error_code"] == "KS-ERR-000"
        assert "xyz" not in body["message"]
