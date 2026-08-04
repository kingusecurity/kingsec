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
from kingsec.application.ai.ports import AIQueryPort
from kingsec.application.ports import AssessmentRepository
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

    def list(self, *, limit: int = 50, offset: int = 0) -> list[Assessment]:
        return []

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
