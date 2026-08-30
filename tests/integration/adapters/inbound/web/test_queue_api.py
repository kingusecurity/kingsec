"""Integration tests for the queue API - KSEC-71-02 (Phase 72).

Phase 71 discovered, and this phase remediates, an authorization bypass
on GET /api/v1/queue/entries: it accepted any authenticated user (any
role) and returned every user's queue entries unfiltered, unlike every
other queue route which already requires admin. These tests exercise
the real router, the real QueueService, the real ListQueue/EnqueueJob
use cases, and a real (in-memory) QueueRepositoryPort implementation -
no mocked authorization logic.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
from kingsec.adapters.inbound.web.dependencies import get_application
from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
from kingsec.application.ports.outbound.queue_repository import QueueRepositoryPort
from kingsec.application.ports.outbound.scheduler_policy import SchedulerPolicyPort
from kingsec.application.ports.queue_service import QueueServicePort
from kingsec.application.queue_service import QueueService
from kingsec.domain import Role
from kingsec.domain.agent import Agent
from kingsec.domain.queue import QueueEntry, QueuePriority, QueueStatistics


class InMemoryQueueRepo(QueueRepositoryPort):
    def __init__(self) -> None:
        self._entries: dict[str, QueueEntry] = {}

    def enqueue(self, entry: QueueEntry) -> None:
        self._entries[entry.entry_id] = entry

    def dequeue(self, entry_id: str) -> QueueEntry | None:
        return self._entries.pop(entry_id, None)

    def peek(self, entry_id: str) -> QueueEntry | None:
        return self._entries.get(entry_id)

    def remove(self, entry_id: str) -> None:
        self._entries.pop(entry_id, None)

    def find_ready(self) -> list[QueueEntry]:
        return []

    def find_waiting(self) -> list[QueueEntry]:
        return list(self._entries.values())

    def find_running(self) -> list[QueueEntry]:
        return []

    def find_all(self) -> list[QueueEntry]:
        return list(self._entries.values())

    def update(self, entry: QueueEntry) -> None:
        self._entries[entry.entry_id] = entry

    def statistics(self) -> QueueStatistics:
        return QueueStatistics(total_entries=len(self._entries))

    def pause(self) -> None:
        pass

    def resume(self) -> None:
        pass


class NoopSchedulerPolicy(SchedulerPolicyPort):
    def select_next_job(self, ready_entries: list[QueueEntry]) -> QueueEntry | None:
        return ready_entries[0] if ready_entries else None

    def allocate_agent(self, entry: QueueEntry, available_agents: list[Agent]) -> Agent | None:
        return None

    def calculate_priority(self, entry: QueueEntry) -> QueuePriority:
        return entry.priority


class ActorHolder:
    def __init__(self, user_id: str = "alice", role: Role = Role.ADMIN) -> None:
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
    return ActorHolder(user_id="alice", role=Role.ADMIN)


@pytest.fixture
def app(actor: ActorHolder) -> FastAPI:
    repo = InMemoryQueueRepo()
    policy = NoopSchedulerPolicy()
    service: QueueServicePort = QueueService(repo, policy)

    class FakeApplication:
        def resolve(self, port: type) -> object:
            if port is QueueServicePort:
                return service
            raise NotImplementedError(str(port))

    async def override_get_current_user() -> CurrentUser:
        return actor.as_current_user()

    from kingsec.adapters.inbound.web.queue_routes import router

    fastapi_app = FastAPI()
    fastapi_app.include_router(router)
    fastapi_app.state.kingsec_app = FakeApplication()
    fastapi_app.dependency_overrides[get_current_user] = override_get_current_user
    fastapi_app.dependency_overrides[get_application] = lambda request=None: fastapi_app.state.kingsec_app
    register_error_handlers(fastapi_app)
    return fastapi_app


def _enqueue_as_admin(client: TestClient, actor: ActorHolder, target: str = "10.99.99.99") -> None:
    actor.user_id = "alice"
    actor.role = Role.ADMIN
    resp = client.post("/api/v1/queue/entry", json={"payload": "scan-payload", "target": target})
    assert resp.status_code == 200, resp.text


class TestQueueListAuthorization:
    def test_admin_can_list_queue_entries(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        _enqueue_as_admin(client, actor)
        resp = client.get("/api/v1/queue/entries")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_admin_response_contains_expected_entry(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        _enqueue_as_admin(client, actor, target="10.0.0.55")
        resp = client.get("/api/v1/queue/entries")
        assert resp.status_code == 200
        entries = resp.json()["entries"]
        assert len(entries) == 1
        assert entries[0]["target"] == "10.0.0.55"
        assert entries[0]["owner_user_id"] == "alice"

    def test_viewer_cannot_get_queue_entries(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        _enqueue_as_admin(client, actor)

        actor.user_id = "mallory"
        actor.role = Role.VIEWER
        resp = client.get("/api/v1/queue/entries")
        assert resp.status_code == 403

    def test_analyst_cannot_get_queue_entries(self, app: FastAPI, actor: ActorHolder) -> None:
        """Queue's existing product policy is admin-only for every other
        operation - ANALYST has no established carve-out, so it is denied
        here too (Phase 72 Section 3: 'do not invent per-user visibility')."""
        client = TestClient(app)
        _enqueue_as_admin(client, actor)

        actor.user_id = "mallory"
        actor.role = Role.ANALYST
        resp = client.get("/api/v1/queue/entries")
        assert resp.status_code == 403

    def test_denied_response_does_not_contain_protected_fields(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        _enqueue_as_admin(client, actor, target="10.99.99.99-internal-hr-system")

        actor.user_id = "mallory"
        actor.role = Role.VIEWER
        resp = client.get("/api/v1/queue/entries")
        assert resp.status_code == 403
        body_text = resp.text
        assert "10.99.99.99-internal-hr-system" not in body_text
        assert "alice" not in body_text
        assert "q-1" not in body_text


class TestQueueIdorRegression:
    """Phase 72 / permanent regression test converting the Phase 71 proof
    (prove_queue_idor.py) into a committed test."""

    def test_alice_enqueues_mallory_denied_admin_allowed(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        _enqueue_as_admin(client, actor, target="10.99.99.99-internal-hr-system")

        actor.user_id = "mallory"
        actor.role = Role.VIEWER
        mallory_resp = client.get("/api/v1/queue/entries")
        assert mallory_resp.status_code == 403
        assert "target" not in mallory_resp.text
        assert "owner_user_id" not in mallory_resp.text
        assert "job_id" not in mallory_resp.text

        actor.user_id = "admin2"
        actor.role = Role.ADMIN
        admin_resp = client.get("/api/v1/queue/entries")
        assert admin_resp.status_code == 200
        entries = admin_resp.json()["entries"]
        assert len(entries) == 1
        assert entries[0]["target"] == "10.99.99.99-internal-hr-system"
        assert entries[0]["owner_user_id"] == "alice"
