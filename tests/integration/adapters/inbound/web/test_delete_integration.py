"""Integration test: delete assessment via HTTP endpoint.

Verifies the full request lifecycle:
  POST /assessments → DELETE /assessments/{id} → GET returns 404
  POST /assessments → DELETE /assessments/{id} → list excludes it
  DELETE twice → second returns 404
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user, require_analyst, require_viewer
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
    StartAssessmentRequest,
    StartAssessmentResponse,
    SubmitAssessmentRequest,
    SubmitAssessmentResponse,
)
from datetime import datetime, timezone

from kingsec.application.ports import TokenClaims
from kingsec.application.ports.inbound.service_api import ServiceAPI
from kingsec.domain import Role


def _make_fake_user() -> CurrentUser:
    now = datetime.now(timezone.utc)
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
        self._assessments: dict[str, dict] = {}
        self._counter = 0

    def create_assessment(
        self, request: CreateAssessmentRequest
    ) -> CreateAssessmentResponse:
        self._counter += 1
        assessment_id = f"asmt-int-{self._counter:03d}"
        self._assessments[assessment_id] = {
            "id": assessment_id,
            "target": f"{request.target_value} ({request.target_type})",
            "status": "authorized",
            "is_authorized": True,
            "created_at": "2026-01-01T00:00:00+00:00",
            "findings_count": 0,
        }
        return CreateAssessmentResponse(
            assessment_id=assessment_id,
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

    def list_assessments(
        self, request: ListAssessmentsRequest
    ) -> ListAssessmentsResponse:
        items = tuple(
            AssessmentSummary(
                assessment_id=a["id"],
                target=a["target"],
                status=a["status"],
                is_authorized=a["is_authorized"],
                created_at=a["created_at"],
                findings_count=a["findings_count"],
            )
            for a in list(self._assessments.values())[request.offset:request.offset + request.limit]
        )
        return ListAssessmentsResponse(
            items=items,
            total=len(self._assessments),
            limit=request.limit,
            offset=request.offset,
        )

    def get_assessment(self, request: GetAssessmentRequest) -> AssessmentView:
        a = self._assessments.get(request.assessment_id)
        if a is None:
            from kingsec.application.errors import AssessmentNotFoundError
            raise AssessmentNotFoundError(request.assessment_id)
        return AssessmentView(
            assessment_id=a["id"],
            target=a["target"],
            status=a["status"],
            is_authorized=a["is_authorized"],
            created_at=a["created_at"],
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

    def delete_assessment(
        self, request: DeleteAssessmentRequest
    ) -> DeleteAssessmentResponse:
        if request.assessment_id not in self._assessments:
            from kingsec.application.errors import AssessmentNotFoundError
            raise AssessmentNotFoundError(request.assessment_id)
        del self._assessments[request.assessment_id]
        return DeleteAssessmentResponse(assessment_id=request.assessment_id)


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


class TestDeleteAssessmentIntegration:
    """Full lifecycle: create → delete → verify gone."""

    def test_create_delete_get_returns_404(self) -> None:
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        # Create assessment
        create_resp = client.post(
            "/api/v1/assessments",
            json={
                "target_value": "10.0.0.1",
                "target_type": "ip_address",
                "authorized_by": "admin@co.com",
                "scope": "10.0.0.1",
            },
        )
        assert create_resp.status_code == 201
        assessment_id = create_resp.json()["assessment_id"]

        # Delete assessment → 204 No Content
        delete_resp = client.delete(f"/api/v1/assessments/{assessment_id}")
        assert delete_resp.status_code == 204
        assert delete_resp.content == b""

        # GET returns 404
        get_resp = client.get(f"/api/v1/assessments/{assessment_id}")
        assert get_resp.status_code == 404
        body = get_resp.json()
        assert body["error_code"] == "KS-RES-001"

    def test_create_delete_list_excludes_deleted(self) -> None:
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        # Create 2 assessments
        for i in range(2):
            client.post(
                "/api/v1/assessments",
                json={
                    "target_value": f"10.0.0.{i + 1}",
                    "target_type": "ip_address",
                    "authorized_by": "admin@co.com",
                    "scope": f"10.0.0.{i + 1}",
                },
            )

        # List shows 2
        list_resp = client.get("/api/v1/assessments")
        assert list_resp.json()["total"] == 2

        # Delete first
        delete_resp = client.delete("/api/v1/assessments/asmt-int-001")
        assert delete_resp.status_code == 204

        # List now shows 1
        list_resp2 = client.get("/api/v1/assessments")
        assert list_resp2.json()["total"] == 1

    def test_delete_nonexistent_returns_404(self) -> None:
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.delete("/api/v1/assessments/asmt-nonexistent")
        assert resp.status_code == 404
        body = resp.json()
        assert body["error_code"] == "KS-RES-001"

    def test_double_delete_returns_404(self) -> None:
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        # Create
        create_resp = client.post(
            "/api/v1/assessments",
            json={
                "target_value": "10.0.0.1",
                "target_type": "ip_address",
                "authorized_by": "admin@co.com",
                "scope": "10.0.0.1",
            },
        )
        assessment_id = create_resp.json()["assessment_id"]

        # First delete → 204
        delete_resp1 = client.delete(f"/api/v1/assessments/{assessment_id}")
        assert delete_resp1.status_code == 204

        # Second delete → 404
        delete_resp2 = client.delete(f"/api/v1/assessments/{assessment_id}")
        assert delete_resp2.status_code == 404
