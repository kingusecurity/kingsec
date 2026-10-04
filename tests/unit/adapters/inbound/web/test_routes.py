"""Tests for FastAPI routes — unit-level with a stubbed ServiceAPI."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.auth import (
    CurrentUser,
    get_current_user,
    require_analyst,
    require_viewer,
)
from kingsec.adapters.inbound.web.dependencies import get_service
from kingsec.application.dto import (
    AssessmentSummary,
    AssessmentView,
    CancelAssessmentRequest,
    CancelAssessmentResponse,
    CreateAssessmentRequest,
    CreateAssessmentResponse,
    DeleteAssessmentRequest,
    DeleteAssessmentResponse,
    FindingView,
    GenerateReportRequest,
    GenerateReportResponse,
    GetAssessmentRequest,
    ListAssessmentsRequest,
    ListAssessmentsResponse,
    SeverityCount,
    SubmitAssessmentRequest,
    SubmitAssessmentResponse,
)
from kingsec.application.ports import TokenClaims, UserRepository
from kingsec.application.ports.inbound.service_api import ServiceAPI
from kingsec.domain import Role


def _make_fake_user() -> CurrentUser:
    now = datetime.now(UTC)
    return CurrentUser(
        user_id="user-001",
        username="testuser",
        role=Role.ANALYST,
        claims=TokenClaims(
            user_id="user-001",
            username="testuser",
            role="analyst",
            token_type="access",
            jti="jti-test-001",
            issued_at=now,
            expires_at=now,
        ),
    )


# --- Stub ServiceAPI ---------------------------------------------------------


class StubServiceAPI(ServiceAPI):
    """Returns deterministic responses for route testing."""

    def __init__(self) -> None:
        self.create_called = False
        self.submit_called = False
        self.cancel_called = False
        self.list_called = False
        self.get_called = False
        self.report_called = False
        self.delete_called = False

    def create_assessment(self, request: CreateAssessmentRequest) -> CreateAssessmentResponse:
        self.create_called = True
        return CreateAssessmentResponse(
            assessment_id="asmt-test-001",
            status="authorized",
            target=f"{request.target_value} ({request.target_type})",
        )

    def submit_assessment(self, request: SubmitAssessmentRequest) -> SubmitAssessmentResponse:
        self.submit_called = True
        return SubmitAssessmentResponse(
            assessment_id=request.assessment_id,
            status="running",
            job_id=request.assessment_id,
        )

    def cancel_assessment(self, request: CancelAssessmentRequest) -> CancelAssessmentResponse:
        self.cancel_called = True
        return CancelAssessmentResponse(
            assessment_id=request.assessment_id,
            status="cancelled",
        )

    def list_assessments(self, request: ListAssessmentsRequest) -> ListAssessmentsResponse:
        self.list_called = True
        return ListAssessmentsResponse(
            items=(
                AssessmentSummary(
                    assessment_id="asmt-test-001",
                    target="10.0.0.5 (ip_address)",
                    status="authorized",
                    is_authorized=True,
                    created_at="2026-01-01T00:00:00+00:00",
                    findings_count=2,
                ),
            ),
            total=1,
            limit=request.limit,
            offset=request.offset,
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

    def generate_report(self, request: GenerateReportRequest) -> GenerateReportResponse:
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

    def delete_assessment(self, request: DeleteAssessmentRequest) -> DeleteAssessmentResponse:
        self.delete_called = True
        return DeleteAssessmentResponse(
            assessment_id=request.assessment_id,
        )


# --- Fixtures ----------------------------------------------------------------


@pytest.fixture
def stub_service() -> StubServiceAPI:
    return StubServiceAPI()


@pytest.fixture
def client(stub_service: StubServiceAPI) -> TestClient:
    """Build a TestClient with a minimal Application-like state."""
    app = FastAPI()

    class _StubUserRepository:
        """Phase 3: /health calls app.resolve(UserRepository) directly -
        an admin already exists, so bootstrap_required reads False, the
        normal case for every route this fixture otherwise exercises."""

        def count_by_role(self, role: Role) -> int:
            return 1

    stub_user_repository = _StubUserRepository()

    # Minimal stub that has a .resolve() method returning the stub service
    # for everything except UserRepository (needed by /health).
    class _StubApp:
        def resolve(self, service_type: type) -> object:
            if service_type is UserRepository:
                return stub_user_repository
            return stub_service

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router

    register_error_handlers(app)
    app.include_router(router)
    app.dependency_overrides[get_service] = lambda: stub_service

    fake_user = _make_fake_user()
    app.dependency_overrides[get_current_user] = lambda: fake_user
    app.dependency_overrides[require_analyst] = lambda: fake_user
    app.dependency_overrides[require_viewer] = lambda: fake_user

    return TestClient(app, raise_server_exceptions=False)


# --- Tests -------------------------------------------------------------------


class TestHealthEndpoint:
    def test_returns_200(self, client: TestClient) -> None:
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_bootstrap_required_false_when_an_admin_exists(self, client: TestClient) -> None:
        # This fixture's own _StubUserRepository.count_by_role always
        # returns 1 (an admin exists) - the normal case for every other
        # route this fixture exercises.
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["bootstrap_required"] is False

    def test_bootstrap_required_true_when_no_admin_exists(self) -> None:
        """Phase 3 (auth hardening): a fresh install, migrated but never
        bootstrapped, must say so on the one endpoint any caller - even
        unauthenticated - can already reach."""
        from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
        from kingsec.adapters.inbound.web.routes import router
        from kingsec.application.ports import UserRepository

        class _NoAdminUserRepository:
            def count_by_role(self, role: Role) -> int:
                return 0

        class _StubApp:
            def resolve(self, service_type: type) -> object:
                if service_type is UserRepository:
                    return _NoAdminUserRepository()
                raise ValueError(f"unexpected resolve() call in this test: {service_type}")

        app = FastAPI()
        app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]
        register_error_handlers(app)
        app.include_router(router)

        resp = TestClient(app, raise_server_exceptions=False).get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["bootstrap_required"] is True

    def test_only_one_router_defines_get_health(self) -> None:
        # Phase 30: health_routes.py used to also define GET /health
        # (health_simple(), returning {"status": "healthy"}) - unreachable
        # dead code, shadowed only because versioning.py happens to include
        # routes.py's router first. test_returns_200 above only proves the
        # current *effective* response is correct; it would keep passing
        # even with a shadowed duplicate reintroduced. This checks each
        # APIRouter's own route list directly (not the fully-wired FastAPI
        # app's internal, version-specific route-resolution machinery) so a
        # future duplicate in either module fails here regardless of
        # inclusion order.
        from kingsec.adapters.inbound.web import health_routes
        from kingsec.adapters.inbound.web import routes as routes_module

        def defines_get(router: object, path: str) -> bool:
            # Each router's own routes already carry its `prefix` baked
            # into `.path` at registration time (both routers use
            # prefix="/api/v1"), so the full path is checked here.
            return any(
                getattr(route, "path", None) == path and "GET" in getattr(route, "methods", set())
                for route in router.routes  # type: ignore[attr-defined]
            )

        assert defines_get(routes_module.router, "/api/v1/health"), "routes.py must own GET /api/v1/health"
        assert not defines_get(health_routes.router, "/api/v1/health"), (
            "health_routes.py must not redefine GET /api/v1/health"
        )


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


class TestListAssessmentsEndpoint:
    def test_returns_200(self, client: TestClient, stub_service: StubServiceAPI) -> None:
        resp = client.get("/api/v1/assessments")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert len(body["items"]) == 1
        assert body["items"][0]["assessment_id"] == "asmt-test-001"
        assert body["items"][0]["target"] == "10.0.0.5 (ip_address)"
        assert body["items"][0]["findings_count"] == 2
        assert stub_service.list_called

    def test_with_pagination_params(self, client: TestClient, stub_service: StubServiceAPI) -> None:
        resp = client.get("/api/v1/assessments?limit=10&offset=5")
        assert resp.status_code == 200
        body = resp.json()
        assert body["limit"] == 10
        assert body["offset"] == 5


class TestDeleteAssessmentEndpoint:
    def test_returns_204(self, client: TestClient, stub_service: StubServiceAPI) -> None:
        resp = client.delete("/api/v1/assessments/asmt-001")
        assert resp.status_code == 204
        assert resp.content == b""
        assert stub_service.delete_called


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

            def list_assessments(self, r):  # type: ignore[override]
                pass

            def get_assessment(self, r):
                from kingsec.application.errors import AssessmentNotFoundError

                raise AssessmentNotFoundError("asmt-missing")

            def generate_report(self, r):  # type: ignore[override]
                pass

            def delete_assessment(self, r):
                from kingsec.application.errors import AssessmentNotFoundError

                raise AssessmentNotFoundError("asmt-missing")

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

        fake_user = _make_fake_user()
        app.dependency_overrides[get_current_user] = lambda: fake_user
        app.dependency_overrides[require_analyst] = lambda: fake_user
        app.dependency_overrides[require_viewer] = lambda: fake_user

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

                raise IllegalStateTransition("not authorized", current="draft", attempted="start")

            def submit_assessment(self, r):
                from kingsec.domain.errors import IllegalStateTransition

                raise IllegalStateTransition("not authorized", current="draft", attempted="start")

            def cancel_assessment(self, r):
                from kingsec.domain.errors import IllegalStateTransition

                raise IllegalStateTransition("already completed", current="completed", attempted="cancelled")

            def list_assessments(self, r):  # type: ignore[override]
                pass

            def get_assessment(self, r):  # type: ignore[override]
                pass

            def generate_report(self, r):  # type: ignore[override]
                pass

            def delete_assessment(self, r):  # type: ignore[override]
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

        fake_user = _make_fake_user()
        app.dependency_overrides[get_current_user] = lambda: fake_user
        app.dependency_overrides[require_analyst] = lambda: fake_user
        app.dependency_overrides[require_viewer] = lambda: fake_user

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

            def list_assessments(self, r):  # type: ignore[override]
                pass

            def get_assessment(self, r):
                raise RuntimeError("database password is xyz")

            def generate_report(self, r):  # type: ignore[override]
                pass

            def delete_assessment(self, r):  # type: ignore[override]
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

        fake_user = _make_fake_user()
        app.dependency_overrides[get_current_user] = lambda: fake_user
        app.dependency_overrides[require_analyst] = lambda: fake_user
        app.dependency_overrides[require_viewer] = lambda: fake_user

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/assessments/asmt-001")
        assert resp.status_code == 500
        body = resp.json()
        assert body["error_code"] == "KS-ERR-000"
        assert "xyz" not in body["message"]
