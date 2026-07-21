"""Integration test: cancel assessment via HTTP endpoint.

Verifies the full request lifecycle:
  POST /assessments → POST /assessments/{id}/cancel → GET /assessments/{id}

The cancel endpoint returns 200 OK with status "cancelled".
"""

from __future__ import annotations

from datetime import UTC, datetime

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
    AssessmentView,
    CancelAssessmentRequest,
    CancelAssessmentResponse,
    CreateAssessmentRequest,
    CreateAssessmentResponse,
    DeleteAssessmentRequest,
    DeleteAssessmentResponse,
    GenerateReportRequest,
    GenerateReportResponse,
    GetAssessmentRequest,
    ListAssessmentsRequest,
    ListAssessmentsResponse,
    StartAssessmentRequest,
    StartAssessmentResponse,
    SubmitAssessmentRequest,
    SubmitAssessmentResponse,
)
from kingsec.application.ports import TokenClaims
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


class _IntegrationService(ServiceAPI):
    """Simulates the full application lifecycle for integration testing."""

    def __init__(self) -> None:
        self._assessment_id: str | None = None

    def create_assessment(
        self, request: CreateAssessmentRequest
    ) -> CreateAssessmentResponse:
        self._assessment_id = "asmt-int-001"
        return CreateAssessmentResponse(
            assessment_id=self._assessment_id,
            status="authorized",
            target=f"{request.target_value} ({request.target_type})",
        )

    def start_assessment(
        self, request: StartAssessmentRequest
    ) -> StartAssessmentResponse:
        return StartAssessmentResponse(
            assessment_id=request.assessment_id,
            status="completed",
            findings_count=0,
            highest_severity=None,
        )

    def submit_assessment(
        self, request: SubmitAssessmentRequest
    ) -> SubmitAssessmentResponse:
        return SubmitAssessmentResponse(
            assessment_id=request.assessment_id,
            status="running",
            job_id=request.assessment_id,
        )

    def cancel_assessment(
        self, request: CancelAssessmentRequest
    ) -> CancelAssessmentResponse:
        return CancelAssessmentResponse(
            assessment_id=request.assessment_id,
            status="cancelled",
        )

    def get_assessment(self, request: GetAssessmentRequest) -> AssessmentView:
        return AssessmentView(
            assessment_id=request.assessment_id,
            target="10.0.0.5 (ip_address)",
            status="cancelled",
            is_authorized=True,
            created_at="2026-01-01T00:00:00+00:00",
            findings=(),
        )

    def generate_report(
        self, request: GenerateReportRequest
    ) -> GenerateReportResponse:
        return GenerateReportResponse(
            assessment_id=request.assessment_id,
            verdict="No findings",
            action_required=False,
            highest_severity=None,
            total_findings=0,
            severity_counts=(),
            artifact_media_type="application/pdf",
            artifact_filename="report.pdf",
            artifact_bytes=512,
        )

    def list_assessments(
        self, request: ListAssessmentsRequest
    ) -> ListAssessmentsResponse:
        return ListAssessmentsResponse(
            items=(),
            total=0,
            limit=request.limit,
            offset=request.offset,
        )

    def delete_assessment(
        self, request: DeleteAssessmentRequest
    ) -> DeleteAssessmentResponse:
        return DeleteAssessmentResponse(
            assessment_id=request.assessment_id,
        )


def _build_app() -> FastAPI:
    service = _IntegrationService()
    app = FastAPI()

    class _StubApp:
        def resolve(self, service_type: type) -> _IntegrationService:
            return service

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router

    register_error_handlers(app)
    app.include_router(router)
    app.dependency_overrides[get_service] = lambda: service

    fake_user = _make_fake_user()
    app.dependency_overrides[get_current_user] = lambda: fake_user
    app.dependency_overrides[require_analyst] = lambda: fake_user
    app.dependency_overrides[require_viewer] = lambda: fake_user

    return app


class TestCancelAssessmentIntegration:
    """Full lifecycle: create → cancel → poll status."""

    def test_create_cancel_poll_lifecycle(self) -> None:
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        # Step 1: Create assessment
        create_resp = client.post(
            "/api/v1/assessments",
            json={
                "target_value": "10.0.0.5",
                "target_type": "ip_address",
                "authorized_by": "admin@co.com",
                "scope": "10.0.0.5",
            },
        )
        assert create_resp.status_code == 201
        assessment_id = create_resp.json()["assessment_id"]
        assert assessment_id == "asmt-int-001"

        # Step 2: Cancel assessment → 200 OK
        cancel_resp = client.post(f"/api/v1/assessments/{assessment_id}/cancel")
        assert cancel_resp.status_code == 200
        body = cancel_resp.json()
        assert body["assessment_id"] == assessment_id
        assert body["status"] == "cancelled"

        # Step 3: Poll assessment status
        get_resp = client.get(f"/api/v1/assessments/{assessment_id}")
        assert get_resp.status_code == 200
        get_body = get_resp.json()
        assert get_body["assessment_id"] == assessment_id
        assert get_body["status"] == "cancelled"
        assert len(get_body["findings"]) == 0
