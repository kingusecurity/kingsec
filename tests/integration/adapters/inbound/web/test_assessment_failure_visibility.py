"""Phase 03 reproduction + regression: failure_reason at the HTTP boundary.

The bug lives inside AssessmentView.from_domain(), so a hand-rolled fake
ServiceAPI (as used by test_background_integration.py) would bypass it
entirely and prove nothing. These tests instead wire the REAL GetAssessment
use case to a real (in-memory) AssessmentRepository, drive an Assessment to
FAILED through the real domain Assessment.fail() method, persist it, and
retrieve it through the real GET /api/v1/assessments/{id} route handler -
exercising from_domain() and the Pydantic AssessmentResponse schema for real.

Written FIRST, before any fix, per the Phase 03 prompt's Step 3.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user, require_viewer
from kingsec.adapters.inbound.web.dependencies import get_service
from kingsec.application.dto import (
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
from kingsec.application.ports.inbound.service_api import ServiceAPI
from kingsec.application.use_cases.get_assessment import GetAssessment
from kingsec.domain import Assessment, Authorization, Role, Target, TargetType
from tests.unit.application.conftest import InMemoryAssessmentRepository


class _GetOnlyService(ServiceAPI):
    """Real GetAssessment wiring; every other operation is unused by these tests."""

    def __init__(self, assessments: InMemoryAssessmentRepository) -> None:
        self._get = GetAssessment(assessments)

    def get_assessment(self, request: GetAssessmentRequest):
        return self._get.execute(request)

    def create_assessment(self, request: CreateAssessmentRequest) -> CreateAssessmentResponse:
        raise NotImplementedError

    def start_assessment(self, request: StartAssessmentRequest) -> StartAssessmentResponse:
        raise NotImplementedError

    def submit_assessment(self, request: SubmitAssessmentRequest) -> SubmitAssessmentResponse:
        raise NotImplementedError

    def cancel_assessment(self, request: CancelAssessmentRequest) -> CancelAssessmentResponse:
        raise NotImplementedError

    def list_assessments(self, request: ListAssessmentsRequest) -> ListAssessmentsResponse:
        raise NotImplementedError

    def generate_report(self, request: GenerateReportRequest) -> GenerateReportResponse:
        raise NotImplementedError

    def delete_assessment(self, request: DeleteAssessmentRequest) -> DeleteAssessmentResponse:
        raise NotImplementedError


def _user(user_id: str, role: Role = Role.VIEWER) -> CurrentUser:
    return CurrentUser(user_id=user_id, username=user_id, role=role)


def _build_app(repo: InMemoryAssessmentRepository, *, current_user: CurrentUser) -> FastAPI:
    app = FastAPI()
    service = _GetOnlyService(repo)

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router

    register_error_handlers(app)
    app.include_router(router)
    app.dependency_overrides[get_service] = lambda: service
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[require_viewer] = lambda: current_user
    return app


def _running(repo: InMemoryAssessmentRepository, *, owner: str | None = None) -> Assessment:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessment.start()
    if owner:
        assessment.set_ownership(owner)
    repo.save(assessment)
    return assessment


def _failed(repo: InMemoryAssessmentRepository, reason: str, *, owner: str | None = None) -> Assessment:
    assessment = _running(repo, owner=owner)
    assessment.fail(reason)
    repo.save(assessment)
    return assessment


class TestFailureReasonHttpVisibility:
    def test_failed_assessment_http_response_contains_failure_reason(self) -> None:
        repo = InMemoryAssessmentRepository()
        assessment = _failed(repo, "scanner subprocess exited with code 1", owner="alice")
        app = _build_app(repo, current_user=_user("alice"))
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get(f"/api/v1/assessments/{assessment.id}")

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "failed"
        assert body["failure_reason"] == "scanner subprocess exited with code 1"

    def test_completed_assessment_failure_reason_is_null_not_absent(self) -> None:
        repo = InMemoryAssessmentRepository()
        assessment = _running(repo, owner="alice")
        assessment.complete()
        repo.save(assessment)
        app = _build_app(repo, current_user=_user("alice"))
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get(f"/api/v1/assessments/{assessment.id}")

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "completed"
        assert "failure_reason" in body
        assert body["failure_reason"] is None

    def test_running_assessment_failure_reason_is_null(self) -> None:
        repo = InMemoryAssessmentRepository()
        assessment = _running(repo, owner="alice")
        app = _build_app(repo, current_user=_user("alice"))
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get(f"/api/v1/assessments/{assessment.id}")

        assert resp.status_code == 200
        assert resp.json()["failure_reason"] is None

    def test_failure_reason_with_special_characters_serializes_correctly(self) -> None:
        repo = InMemoryAssessmentRepository()
        reason = 'connection refused: "10.0.0.99:443"\nretrying failed\ttab and unicode: café'
        assessment = _failed(repo, reason, owner="alice")
        app = _build_app(repo, current_user=_user("alice"))
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get(f"/api/v1/assessments/{assessment.id}")

        assert resp.status_code == 200
        assert resp.json()["failure_reason"] == reason


class TestFailureReasonInheritsExistingOwnershipGate:
    """Step 4 concluded failure_reason gets no NEW restriction: it is exposed
    to whoever the EXISTING check_assessment_access() gate already lets read
    the assessment (owner or admin), same as every other AssessmentView field.
    These tests prove that inheritance holds, not a new access-control path."""

    def test_non_owner_non_admin_cannot_read_the_assessment_at_all(self) -> None:
        repo = InMemoryAssessmentRepository()
        assessment = _failed(repo, "internal detail", owner="alice")
        app = _build_app(repo, current_user=_user("bob"))
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get(f"/api/v1/assessments/{assessment.id}")

        # Existing check_assessment_access() behavior: a non-owner gets 404,
        # not a 200 with failure_reason stripped out - the field never gets
        # a chance to leak because the whole resource is denied first.
        assert resp.status_code == 404

    def test_admin_can_read_another_users_failure_reason(self) -> None:
        repo = InMemoryAssessmentRepository()
        assessment = _failed(repo, "scanner timed out", owner="alice")
        app = _build_app(repo, current_user=_user("admin-1", role=Role.ADMIN))
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get(f"/api/v1/assessments/{assessment.id}")

        assert resp.status_code == 200
        assert resp.json()["failure_reason"] == "scanner timed out"

    def test_owner_can_read_own_failure_reason(self) -> None:
        repo = InMemoryAssessmentRepository()
        assessment = _failed(repo, "scanner timed out", owner="alice")
        app = _build_app(repo, current_user=_user("alice"))
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get(f"/api/v1/assessments/{assessment.id}")

        assert resp.status_code == 200
        assert resp.json()["failure_reason"] == "scanner timed out"
