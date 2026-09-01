from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from kingsec.application.ports.agent_service import AgentServicePort
from kingsec.domain import Role
from kingsec.domain.agent import (
    Agent,
    AgentArchitecture,
    AgentCapability,
    AgentHealth,
    AgentId,
    AgentPlatform,
    AgentState,
    AgentStatistics,
)


@pytest.fixture
def mock_service() -> MagicMock:
    service = MagicMock(spec=AgentServicePort)
    service.register.return_value = Agent(
        id=AgentId("agent-1"),
        name="Test Agent",
        platform=AgentPlatform.LINUX,
        architecture=AgentArchitecture.AMD64,
        version="1.0.0",
        hostname="host-1",
        state=AgentState.ONLINE,
        capability=AgentCapability(),
        api_key_hash="abc",
    )
    service.list_agents.return_value = []
    service.get_agent.return_value = None
    service.disable_agent.return_value = Agent(
        id=AgentId("agent-1"),
        name="Test",
        platform=AgentPlatform.LINUX,
        architecture=AgentArchitecture.AMD64,
        version="1.0",
        hostname="h",
        state=AgentState.DISABLED,
        capability=AgentCapability(),
        api_key_hash="",
    )
    service.enable_agent.return_value = Agent(
        id=AgentId("agent-1"),
        name="Test",
        platform=AgentPlatform.LINUX,
        architecture=AgentArchitecture.AMD64,
        version="1.0",
        hostname="h",
        state=AgentState.ONLINE,
        capability=AgentCapability(),
        api_key_hash="",
    )
    service.assign_next_job.return_value = "job-abc"
    return service


@pytest.fixture
def app(mock_service: MagicMock) -> TestClient:
    with patch("kingsec.bootstrap.application.Application") as MockApp:
        app_instance = MockApp()
        app_instance.resolve.return_value = mock_service

        from fastapi import FastAPI

        app = FastAPI()
        from kingsec.adapters.inbound.web.agent_routes import router

        app.include_router(router)
        app.state.kingsec_app = app_instance
        client = TestClient(app)
        from kingsec.adapters.inbound.web.auth import get_current_user

        app.dependency_overrides[get_current_user] = lambda: type(
            "User", (), {"id": "admin", "username": "admin", "role": Role.ADMIN, "claims": None}
        )()
        return client


class TestAgentRoutes:
    def test_register_agent(self, app: TestClient) -> None:
        resp = app.post(
            "/api/v1/agents/register",
            json={
                "agent_id": "agent-1",
                "name": "Test Agent",
                "platform": "linux",
                "architecture": "amd64",
                "version": "1.0.0",
                "hostname": "host-1",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent"]["id"] == "agent-1"

    def test_heartbeat(self, app: TestClient) -> None:
        resp = app.post(
            "/api/v1/agents/heartbeat",
            json={
                "agent_id": "agent-1",
                "state": "online",
                "cpu_usage": 45.0,
                "memory_usage": 60.0,
            },
        )
        assert resp.status_code == 200
        assert resp.json()["message"] == "Heartbeat received"

    def test_list_agents_empty(self, app: TestClient) -> None:
        resp = app.get("/api/v1/agents")
        assert resp.status_code == 200
        assert resp.json()["agents"] == []

    def test_get_agent_found(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.get_agent.return_value = Agent(
            id=AgentId("agent-1"),
            name="Test",
            platform=AgentPlatform.LINUX,
            architecture=AgentArchitecture.AMD64,
            version="1.0",
            hostname="h",
            state=AgentState.ONLINE,
            capability=AgentCapability(),
            api_key_hash="",
            health=AgentHealth(cpu_usage_percent=50.0),
            statistics=AgentStatistics(total_jobs_completed=5),
        )
        resp = app.get("/api/v1/agents/agent-1")
        assert resp.status_code == 200
        assert resp.json()["id"] == "agent-1"
        assert resp.json()["jobs_completed"] == 5

    def test_get_agent_not_found(self, app: TestClient) -> None:
        resp = app.get("/api/v1/agents/nonexistent")
        assert resp.status_code == 404

    def test_disable_agent(self, app: TestClient) -> None:
        resp = app.post("/api/v1/agents/agent-1/disable")
        assert resp.status_code == 200
        assert resp.json()["state"] == "disabled"

    def test_enable_agent(self, app: TestClient) -> None:
        resp = app.post("/api/v1/agents/agent-1/enable")
        assert resp.status_code == 200
        assert resp.json()["state"] == "online"

    def test_remove_agent(self, app: TestClient) -> None:
        resp = app.delete("/api/v1/agents/agent-1")
        assert resp.status_code == 200

    def test_assign_next_job(self, app: TestClient) -> None:
        resp = app.post("/api/v1/agents/jobs/next", json={"agent_id": "agent-1"})
        assert resp.status_code == 200
        assert resp.json()["job_id"] == "job-abc"

    def test_report_progress(self, app: TestClient) -> None:
        resp = app.post(
            "/api/v1/agents/jobs/progress",
            json={
                "agent_id": "agent-1",
                "job_id": "job-1",
                "progress": 50.0,
            },
        )
        assert resp.status_code == 200

    def test_complete_job(self, app: TestClient) -> None:
        resp = app.post(
            "/api/v1/agents/jobs/complete",
            json={
                "agent_id": "agent-1",
                "job_id": "job-1",
            },
        )
        assert resp.status_code == 200

    def test_fail_job(self, app: TestClient) -> None:
        resp = app.post(
            "/api/v1/agents/jobs/fail",
            json={
                "agent_id": "agent-1",
                "job_id": "job-1",
                "error": "scan failed",
            },
        )
        assert resp.status_code == 200


class TestAdminExceptionDisclosureConsolidation:
    """KSEC-87-01, representative-route coverage (Section 5.3): proves
    admin_operation_error() is actually wired into a real route end to
    end, both for the safe (ApplicationError) and unsafe (unexpected)
    cases - not just tested in isolation against the helper function
    itself (see test_error_handlers.py::TestAdminOperationError)."""

    def test_a_known_application_error_still_reaches_the_client_with_its_own_message(
        self, app: TestClient, mock_service: MagicMock
    ) -> None:
        from kingsec.application.errors import AgentNotFoundError

        mock_service.disable_agent.side_effect = AgentNotFoundError("Agent 'agent-1' not found")

        resp = app.post("/api/v1/agents/agent-1/disable")

        assert resp.status_code == 404
        assert resp.json()["detail"] == "Agent 'agent-1' not found"

    def test_an_unexpected_exception_does_not_leak_its_message_to_the_client(
        self, app: TestClient, mock_service: MagicMock
    ) -> None:
        """Route still admin-only (authorization untouched); the response
        must never contain the underlying (here, deliberately
        path-shaped) exception text."""
        mock_service.disable_agent.side_effect = RuntimeError(
            "sqlite3.OperationalError: database is locked: /var/lib/kingsec/kingsec.db"
        )
        real_client = TestClient(app.app, raise_server_exceptions=False)

        resp = real_client.post("/api/v1/agents/agent-1/disable")

        assert resp.status_code == 500
        body_text = resp.text
        assert "/var/lib/kingsec/kingsec.db" not in body_text
        assert "sqlite3.OperationalError" not in body_text
        assert "database is locked" not in body_text
