"""Integration tests for the pipeline API - KSEC-71-01 (Phase 72).

Phase 71 discovered, and this phase remediates, a BOLA/IDOR on pipeline
executions: GET /api/v1/pipelines/{pipeline_id} and GET /api/v1/pipelines
accepted any authenticated user with zero owner/admin check. These tests
exercise the real router, the real PipelineService, the real GetPipeline/
ListPipelines use cases, and a real (in-memory) PipelineRepositoryPort
implementation - no mocked authorization logic - proving the fix and
permanently guarding against regression.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
from kingsec.adapters.inbound.web.dependencies import get_application
from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
from kingsec.application.pipeline_service import PipelineService
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.pipeline_orchestrator import PipelineOrchestratorPort
from kingsec.application.ports.outbound.pipeline_repository import PipelineRepositoryPort
from kingsec.application.ports.pipeline_service import PipelineServicePort
from kingsec.domain import Role
from kingsec.domain.audit import AuditEntry
from kingsec.domain.pipeline import PipelineExecution


class InMemoryPipelineRepo(PipelineRepositoryPort):
    def __init__(self) -> None:
        self._store: dict[str, PipelineExecution] = {}

    def save(self, execution: PipelineExecution) -> None:
        self._store[execution.pipeline_id.value] = execution

    def find_by_id(self, pipeline_id: str) -> PipelineExecution | None:
        return self._store.get(pipeline_id)

    def find_all(self) -> list[PipelineExecution]:
        return list(self._store.values())

    def find_by_owner(self, owner_user_id: str) -> list[PipelineExecution]:
        return [e for e in self._store.values() if e.owner_user_id == owner_user_id]

    def find_by_state(self, state: str) -> list[PipelineExecution]:
        return [e for e in self._store.values() if e.state.value == state]

    def delete(self, pipeline_id: str) -> None:
        self._store.pop(pipeline_id, None)


class NoopOrchestrator(PipelineOrchestratorPort):
    def advance(self, execution: PipelineExecution) -> PipelineExecution:
        return execution

    def cancel(self, execution: PipelineExecution) -> PipelineExecution:
        return execution

    def retry(self, execution: PipelineExecution) -> PipelineExecution:
        return execution

    def pause(self, execution: PipelineExecution) -> PipelineExecution:
        return execution

    def resume(self, execution: PipelineExecution) -> PipelineExecution:
        return execution


class FakeAudit(AuditPublisher):
    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        self.entries.append(entry)


class ActorHolder:
    """Mutable holder for the currently-authenticated test user - lets a
    single TestClient session switch identities mid-test (Alice creates,
    then Mallory attacks), matching the pattern established in
    test_schedule_api.py (Phase 70)."""

    def __init__(self, user_id: str = "alice", role: Role = Role.ANALYST) -> None:
        self.user_id = user_id
        self.role = role

    def as_current_user(self) -> CurrentUser:
        return CurrentUser(
            user_id=self.user_id,
            username=self.user_id,
            role=self.role,
            claims=None,  # type: ignore[arg-type]
        )


@pytest.fixture
def actor() -> ActorHolder:
    return ActorHolder(user_id="alice", role=Role.ANALYST)


@pytest.fixture
def app(actor: ActorHolder) -> FastAPI:
    repo = InMemoryPipelineRepo()
    orchestrator = NoopOrchestrator()
    audit = FakeAudit()
    service: PipelineServicePort = PipelineService(repo, orchestrator, audit)

    class FakeApplication:
        def resolve(self, port: type) -> object:
            if port is PipelineServicePort:
                return service
            raise NotImplementedError(str(port))

    async def override_get_current_user() -> CurrentUser:
        return actor.as_current_user()

    from kingsec.adapters.inbound.web.pipeline_routes import router

    fastapi_app = FastAPI()
    fastapi_app.include_router(router)
    fastapi_app.state.kingsec_app = FakeApplication()
    fastapi_app.state.audit = audit
    fastapi_app.dependency_overrides[get_current_user] = override_get_current_user
    fastapi_app.dependency_overrides[get_application] = lambda request=None: fastapi_app.state.kingsec_app
    register_error_handlers(fastapi_app)
    return fastapi_app


def _start_as_alice(client: TestClient, actor: ActorHolder, target: str = "10.99.99.99") -> str:
    actor.user_id = "alice"
    actor.role = Role.ADMIN  # /start is admin-only, unrelated to this phase's fix
    resp = client.post("/api/v1/pipelines/start", json={"target": target})
    assert resp.status_code == 200, resp.text
    pid: str = resp.json()["pipeline"]["pipeline_id"]
    actor.role = Role.ANALYST  # restore Alice to a non-admin role for the rest of the test
    return pid


class TestGetPipelineOwnership:
    def test_owner_can_get_own_pipeline(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        pid = _start_as_alice(client, actor)
        resp = client.get(f"/api/v1/pipelines/{pid}")
        assert resp.status_code == 200
        assert resp.json()["pipeline_id"] == pid

    def test_admin_can_get_another_users_pipeline(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        pid = _start_as_alice(client, actor)
        actor.user_id = "admin1"
        actor.role = Role.ADMIN
        resp = client.get(f"/api/v1/pipelines/{pid}")
        assert resp.status_code == 200
        assert resp.json()["pipeline_id"] == pid

    def test_non_owner_viewer_cannot_get_another_users_pipeline(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        pid = _start_as_alice(client, actor, target="10.99.99.99-internal-payroll-db")

        actor.user_id = "mallory"
        actor.role = Role.VIEWER
        resp = client.get(f"/api/v1/pipelines/{pid}")
        assert resp.status_code == 404
        body = resp.json()
        assert "10.99.99.99-internal-payroll-db" not in str(body)
        assert "alice" not in str(body)

    def test_non_owner_analyst_cannot_get_another_users_pipeline(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        pid = _start_as_alice(client, actor)

        actor.user_id = "mallory"
        actor.role = Role.ANALYST
        resp = client.get(f"/api/v1/pipelines/{pid}")
        assert resp.status_code == 404

    def test_unknown_pipeline_still_returns_404(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        actor.user_id = "mallory"
        actor.role = Role.VIEWER
        resp = client.get("/api/v1/pipelines/does-not-exist")
        assert resp.status_code == 404


class TestListPipelinesOwnership:
    def test_owner_sees_own_pipeline_in_list(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        _start_as_alice(client, actor)
        resp = client.get("/api/v1/pipelines")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_admin_sees_all_pipelines(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        _start_as_alice(client, actor)
        actor.user_id = "admin1"
        actor.role = Role.ADMIN
        resp = client.post("/api/v1/pipelines/start", json={"target": "10.0.0.2"})
        assert resp.status_code == 200
        resp2 = client.get("/api/v1/pipelines")
        assert resp2.status_code == 200
        assert resp2.json()["total"] == 2

    def test_non_owner_does_not_see_another_users_pipeline_in_list(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        _start_as_alice(client, actor, target="10.99.99.99-internal-payroll-db")

        actor.user_id = "mallory"
        actor.role = Role.VIEWER
        resp = client.get("/api/v1/pipelines")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["pipelines"] == []
        assert "10.99.99.99-internal-payroll-db" not in str(body)


class TestPipelineIdorRegression:
    """Phase 72 / permanent regression test converting the Phase 71 proof
    (prove_pipeline_idor.py) into a committed test."""

    def test_alice_mallory_admin_end_to_end(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)

        pid = _start_as_alice(client, actor, target="10.99.99.99-internal-payroll-db")

        actor.user_id = "mallory"
        actor.role = Role.VIEWER
        get_resp = client.get(f"/api/v1/pipelines/{pid}")
        assert get_resp.status_code == 404
        assert "10.99.99.99-internal-payroll-db" not in get_resp.text

        list_resp = client.get("/api/v1/pipelines")
        assert list_resp.status_code == 200
        assert list_resp.json()["total"] == 0
        assert "10.99.99.99-internal-payroll-db" not in list_resp.text

        actor.user_id = "alice"
        actor.role = Role.ANALYST
        alice_view = client.get(f"/api/v1/pipelines/{pid}")
        assert alice_view.status_code == 200
        assert alice_view.json()["target"] == "10.99.99.99-internal-payroll-db"

        actor.user_id = "admin1"
        actor.role = Role.ADMIN
        admin_view = client.get(f"/api/v1/pipelines/{pid}")
        assert admin_view.status_code == 200
        assert admin_view.json()["owner_user_id"] == "alice"
