"""Behavioral-equivalence test for ai_routes.py's AIError -> ExternalServiceError swap.

ai_routes.py used to catch the infrastructure-owned ``AIError`` directly (an
import-linter violation: an adapter reaching into infrastructure). It now
catches the shared-kernel base ``ExternalServiceError`` instead, since
``AIError`` subclasses it. This test proves that swap didn't change the
user-facing HTTP response: an ``AIError`` raised by the AI provider must
still produce the same 502 status and ``{"detail": ...}`` body as before.
"""

from __future__ import annotations

import builtins
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
from kingsec.application.ai.ai_chat import AIChatService
from kingsec.application.ai.executive_summary import ExecutiveSummaryService
from kingsec.application.ai.explain_finding import ExplainFindingService
from kingsec.application.ai.ports import AIQueryPort
from kingsec.application.ai.remediation_assistant import RemediationAssistantService
from kingsec.application.ports import AssessmentRepository
from kingsec.application.ports.repositories import AssessmentPage
from kingsec.bootstrap.application import Application
from kingsec.bootstrap.container import Container
from kingsec.domain import Role
from kingsec.domain.assessment import Assessment
from kingsec.domain.identifiers import AssessmentId
from kingsec.infrastructure.ai.errors import AIError
from kingsec.infrastructure.config import load_settings

from .test_session_api import TokenClaims


class _RaisingAIQueryPort(AIQueryPort):
    """Simulates the real behavior: the AI provider failed, translated to AIError."""

    def generate(self, system_prompt: str, user_prompt: str, **kwargs: Any) -> str:
        raise AIError("AI provider unreachable")

    def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        raise AIError("AI provider unreachable")

    def health(self) -> dict[str, Any]:
        return {"status": "unknown"}


class _EmptyAssessmentRepository(AssessmentRepository):
    def save(self, assessment: Assessment) -> None:
        pass

    def get(self, assessment_id: AssessmentId) -> Assessment:
        raise AssertionError("not expected to be called in this test")

    def list(self, *, limit: int = 50, offset: int = 0) -> AssessmentPage:
        return AssessmentPage(items=())

    def find_by_schedule_occurrence_id(self, occurrence_id: str) -> list[Assessment]:
        return []

    def find_running(self) -> list[Assessment]:
        return []

    def find_running_ids(self) -> list[str]:
        return []

    def force_fail_running(self, assessment_id: str, reason: str) -> bool:
        return False

    def delete(self, assessment_id: AssessmentId) -> None:
        pass

    def search_findings(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        assessment_id: str | None = None,
        search: str | None = None,
        order_by: str = "discovered_at",
        order_dir: str = "desc",
        limit: int = 50,
        offset: int = 0,
        requesting_user: str = "",
        is_admin: bool = False,
    ) -> tuple[builtins.list[Any], int]:
        return [], 0


async def override_get_current_user() -> CurrentUser:
    return CurrentUser(
        user_id="u1",
        username="admin",
        role=Role.ADMIN,
        claims=TokenClaims(
            user_id="u1",
            username="admin",
            role="admin",
            token_type="access",
            jti="test-jti",
            issued_at=None,
            expires_at=None,
        ),
    )


@pytest.fixture
def app() -> FastAPI:
    container = Container()
    container.register_instance(AssessmentRepository, _EmptyAssessmentRepository())
    container.register_instance(AIChatService, AIChatService(ai=_RaisingAIQueryPort()))

    settings = load_settings()
    application = Application(
        settings=settings,
        container=container,
        exception_handlers=None,
        logger=None,
        ensure_directories=False,
    )

    fastapi_app = FastAPI()
    fastapi_app.state.kingsec_app = application
    fastapi_app.dependency_overrides[get_current_user] = override_get_current_user

    from kingsec.adapters.inbound.web.ai_routes import router

    fastapi_app.include_router(router)
    register_error_handlers(fastapi_app)

    return fastapi_app


class TestAIErrorMapsTo502:
    def test_chat_endpoint_returns_502_with_detail_body_on_ai_error(self, app: FastAPI) -> None:
        client = TestClient(app)
        resp = client.post("/api/v1/ai/chat", json={"question": "What is my biggest risk?"})
        assert resp.status_code == 502
        assert resp.json() == {"detail": "[KS-EXT-001] AI provider unreachable"}


# ── KSEC-84-01: AI endpoints must not disclose another user's assessment ────


class _StubExecutiveSummaryService:
    def generate(self, assessment: Assessment) -> dict[str, Any]:
        return {"summary": "leaked cross-tenant data"}


class _StubExplainFindingService:
    def explain(self, finding: Any) -> dict[str, Any]:
        return {"explanation": "leaked cross-tenant data"}


class _StubRemediationAssistantService:
    def plan(self, findings: list[Any]) -> dict[str, Any]:
        return {"plan": "leaked cross-tenant data"}


class _StubAIChatService:
    def chat(self, question: str, history: list[Any], assessment: Assessment | None) -> dict[str, Any]:
        return {"answer": "leaked cross-tenant data"}


def _owned_assessment_repo() -> tuple[Any, str, str]:
    """A real (in-memory) AssessmentRepository holding one assessment owned
    by "alice", with one real finding - not a mock of the ownership check
    itself."""
    from kingsec.application import SubmitAssessment, SubmitAssessmentRequest
    from kingsec.domain import Assessment, Authorization, Target, TargetType
    from tests.unit.application.conftest import InMemoryAssessmentRepository, StubScanner, make_findings

    class _InlineJobRunner:
        """Runs the submitted job synchronously, in-thread - deterministic for tests."""

        def submit(self, job_id: str, fn: Any, *args: Any, **kwargs: Any) -> None:
            fn()

        def is_running(self, job_id: str) -> bool:
            return False

        def shutdown(self, wait: bool = True) -> None:
            pass

    repo = InMemoryAssessmentRepository()
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    repo.save(assessment)
    SubmitAssessment(repo, StubScanner(make_findings()), _InlineJobRunner()).execute(
        SubmitAssessmentRequest(str(assessment.id), is_admin=True)
    )
    assessment.set_ownership("alice")
    repo.save(assessment)
    finding_id = str(assessment.findings[0].id)
    return repo, str(assessment.id), finding_id


def _app_for_role(role: Role, user_id: str, repo: Any) -> FastAPI:
    async def override_user() -> CurrentUser:
        return CurrentUser(
            user_id=user_id,
            username=user_id,
            role=role,
            claims=TokenClaims(
                user_id=user_id, username=user_id, role=role.name.lower(), token_type="access",
                jti="test-jti", issued_at=None, expires_at=None,
            ),
        )

    container = Container()
    container.register_instance(AssessmentRepository, repo)
    container.register_instance(ExecutiveSummaryService, _StubExecutiveSummaryService())
    container.register_instance(ExplainFindingService, _StubExplainFindingService())
    container.register_instance(RemediationAssistantService, _StubRemediationAssistantService())
    container.register_instance(AIChatService, _StubAIChatService())

    settings = load_settings()
    application = Application(settings=settings, container=container, exception_handlers=None, logger=None, ensure_directories=False)

    fastapi_app = FastAPI()
    fastapi_app.state.kingsec_app = application
    fastapi_app.dependency_overrides[get_current_user] = override_user

    from kingsec.adapters.inbound.web.ai_routes import router

    fastapi_app.include_router(router)
    register_error_handlers(fastapi_app)
    return fastapi_app


class TestAIEndpointsEnforceAssessmentOwnership:
    def test_executive_summary_rejects_non_owner(self) -> None:
        repo, assessment_id, _ = _owned_assessment_repo()
        app = _app_for_role(Role.VIEWER, "bob", repo)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/ai/executive-summary", json={"assessment_id": assessment_id})
        assert resp.status_code == 404
        assert "leaked" not in resp.text

    def test_executive_summary_allows_owner(self) -> None:
        repo, assessment_id, _ = _owned_assessment_repo()
        app = _app_for_role(Role.VIEWER, "alice", repo)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/ai/executive-summary", json={"assessment_id": assessment_id})
        assert resp.status_code == 200

    def test_executive_summary_allows_admin(self) -> None:
        repo, assessment_id, _ = _owned_assessment_repo()
        app = _app_for_role(Role.ADMIN, "carol", repo)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/ai/executive-summary", json={"assessment_id": assessment_id})
        assert resp.status_code == 200

    def test_remediation_plan_rejects_non_owner(self) -> None:
        repo, assessment_id, _ = _owned_assessment_repo()
        app = _app_for_role(Role.VIEWER, "bob", repo)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/ai/remediation-plan", json={"assessment_id": assessment_id})
        assert resp.status_code == 404
        assert "leaked" not in resp.text

    def test_explain_finding_rejects_non_owner(self) -> None:
        repo, assessment_id, finding_id = _owned_assessment_repo()
        app = _app_for_role(Role.VIEWER, "bob", repo)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/ai/explain-finding",
            json={"assessment_id": assessment_id, "finding_id": finding_id},
        )
        assert resp.status_code == 404
        assert "leaked" not in resp.text

    def test_explain_finding_allows_owner(self) -> None:
        repo, assessment_id, finding_id = _owned_assessment_repo()
        app = _app_for_role(Role.VIEWER, "alice", repo)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/ai/explain-finding",
            json={"assessment_id": assessment_id, "finding_id": finding_id},
        )
        assert resp.status_code == 200

    def test_chat_with_assessment_id_rejects_non_owner(self) -> None:
        repo, assessment_id, _ = _owned_assessment_repo()
        app = _app_for_role(Role.VIEWER, "bob", repo)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/ai/chat",
            json={"question": "What is my biggest risk?", "assessment_id": assessment_id},
        )
        assert resp.status_code == 404
        assert "leaked" not in resp.text

    def test_chat_with_assessment_id_allows_owner(self) -> None:
        repo, assessment_id, _ = _owned_assessment_repo()
        app = _app_for_role(Role.VIEWER, "alice", repo)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/ai/chat",
            json={"question": "What is my biggest risk?", "assessment_id": assessment_id},
        )
        assert resp.status_code == 200
