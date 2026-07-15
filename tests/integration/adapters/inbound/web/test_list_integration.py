"""Integration test: list assessments via HTTP endpoint.

Verifies the full request lifecycle:
  POST /assessments (create multiple) → GET /assessments (list them)

The list endpoint returns 200 OK with paginated results.
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
from kingsec.application.ports import TokenClaims
from kingsec.application.ports.inbound.service_api import ServiceAPI
from kingsec.domain import Role
from datetime import datetime, timezone


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
        self._assessments: list[dict] = []

    def create_assessment(
        self, request: CreateAssessmentRequest
    ) -> CreateAssessmentResponse:
        assessment_id = f"asmt-int-{len(self._assessments) + 1:03d}"
        self._assessments.append({
            "id": assessment_id,
            "target": f"{request.target_value} ({request.target_type})",
            "status": "authorized",
            "is_authorized": True,
            "created_at": "2026-01-01T00:00:00+00:00",
            "findings_count": 0,
        })
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
            for a in self._assessments[request.offset:request.offset + request.limit]
        )
        return ListAssessmentsResponse(
            items=items,
            total=len(self._assessments),
            limit=request.limit,
            offset=request.offset,
        )

    def get_assessment(self, request: GetAssessmentRequest) -> AssessmentView:
        for a in self._assessments:
            if a["id"] == request.assessment_id:
                return AssessmentView(
                    assessment_id=a["id"],
                    target=a["target"],
                    status=a["status"],
                    is_authorized=a["is_authorized"],
                    created_at=a["created_at"],
                    findings=(),
                )
        from kingsec.application.errors import AssessmentNotFoundError
        raise AssessmentNotFoundError(request.assessment_id)

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


class TestListAssessmentsIntegration:
    """Full lifecycle: create multiple → list → verify."""

    def test_create_then_list(self) -> None:
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        # Create 3 assessments
        for i in range(3):
            create_resp = client.post(
                "/api/v1/assessments",
                json={
                    "target_value": f"10.0.0.{i + 1}",
                    "target_type": "ip_address",
                    "authorized_by": "admin@co.com",
                    "scope": f"10.0.0.{i + 1}",
                },
            )
            assert create_resp.status_code == 201

        # List all assessments
        list_resp = client.get("/api/v1/assessments")
        assert list_resp.status_code == 200
        body = list_resp.json()
        assert body["total"] == 3
        assert len(body["items"]) == 3
        assert body["items"][0]["assessment_id"] == "asmt-int-001"
        assert body["items"][2]["assessment_id"] == "asmt-int-003"

    def test_list_with_pagination(self) -> None:
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        # Create 5 assessments
        for i in range(5):
            client.post(
                "/api/v1/assessments",
                json={
                    "target_value": f"10.0.0.{i + 1}",
                    "target_type": "ip_address",
                    "authorized_by": "admin@co.com",
                    "scope": f"10.0.0.{i + 1}",
                },
            )

        # Page 1
        resp1 = client.get("/api/v1/assessments?limit=2&offset=0")
        assert resp1.status_code == 200
        body1 = resp1.json()
        assert len(body1["items"]) == 2
        assert body1["total"] == 5

        # Page 2
        resp2 = client.get("/api/v1/assessments?limit=2&offset=2")
        assert resp2.status_code == 200
        body2 = resp2.json()
        assert len(body2["items"]) == 2

        # Page 3 (partial)
        resp3 = client.get("/api/v1/assessments?limit=2&offset=4")
        assert resp3.status_code == 200
        body3 = resp3.json()
        assert len(body3["items"]) == 1

    def test_list_empty_database(self) -> None:
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/api/v1/assessments")
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["total"] == 0
