"""Phase 03: full round-trip proof for failure_reason.

Assessment.fail() -> real SQLite persistence (SQLAlchemyAssessmentRepository)
-> real GetAssessment use case -> real AssessmentView.from_domain() -> real
GET /api/v1/assessments/{id} HTTP response, all in one continuous test - not
just each layer's own isolated test (mapper round-trip in
test_assessment_repository.py, DTO in test_get_assessment_failure_reason.py,
HTTP in test_assessment_failure_visibility.py all already cover their own
layer; this proves the whole chain together, unmodified end to end).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user, require_viewer
from kingsec.adapters.inbound.web.dependencies import get_service
from kingsec.application.dto import GetAssessmentRequest
from kingsec.application.ports.inbound.service_api import ServiceAPI
from kingsec.application.use_cases.get_assessment import GetAssessment
from kingsec.domain import Assessment, AssessmentId, Authorization, Role, Target, TargetType
from kingsec.infrastructure.persistence import create_database_engine, create_schema
from kingsec.infrastructure.persistence.repositories import SQLAlchemyAssessmentRepository


@pytest.fixture
def engine():
    eng = create_database_engine(url="sqlite://")
    create_schema(eng)
    try:
        yield eng
    finally:
        eng.dispose()


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s
        s.rollback()


@pytest.fixture
def repo(session):
    return SQLAlchemyAssessmentRepository(session)


class _GetOnlyService(ServiceAPI):
    def __init__(self, get_use_case: GetAssessment) -> None:
        self._get = get_use_case

    def get_assessment(self, request: GetAssessmentRequest):
        return self._get.execute(request)

    def create_assessment(self, request): raise NotImplementedError
    def start_assessment(self, request): raise NotImplementedError
    def submit_assessment(self, request): raise NotImplementedError
    def cancel_assessment(self, request): raise NotImplementedError
    def list_assessments(self, request): raise NotImplementedError
    def generate_report(self, request): raise NotImplementedError
    def delete_assessment(self, request): raise NotImplementedError


def _build_app(repo: SQLAlchemyAssessmentRepository, *, current_user: CurrentUser) -> FastAPI:
    app = FastAPI()
    service = _GetOnlyService(GetAssessment(repo))

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router

    register_error_handlers(app)
    app.include_router(router)
    app.dependency_overrides[get_service] = lambda: service
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[require_viewer] = lambda: current_user
    return app


class TestFailureReasonFullRoundTrip:
    def test_fail_persist_retrieve_via_real_sqlite_then_real_http_endpoint(
        self, repo: SQLAlchemyAssessmentRepository, session: Session
    ) -> None:
        assessment = Assessment(
            assessment_id=AssessmentId.generate(),
            target=Target("10.0.0.5", TargetType.IP_ADDRESS),
            created_at=datetime.now(UTC),
        )
        assessment.authorize(Authorization("tester", datetime.now(UTC), scope="10.0.0.5"))
        assessment.start()
        reason = "The security scan could not be completed."
        assessment.fail(reason)
        assessment.set_ownership("alice")

        repo.save(assessment)
        session.flush()
        session.expunge_all()  # force a genuine reload from SQLite, not the identity map

        app = _build_app(repo, current_user=CurrentUser(user_id="alice", username="alice", role=Role.VIEWER))
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get(f"/api/v1/assessments/{assessment.id}")

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "failed"
        assert body["failure_reason"] == reason
