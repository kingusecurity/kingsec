"""Integration tests for the scheduled scan API."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
from kingsec.application.jobs import InMemoryJobService
from kingsec.application.ports.job_service import JobServicePort
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.clock_port import ClockPort
from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort
from kingsec.application.ports.outbound.scheduler_service import SchedulerServicePort
from kingsec.application.use_cases.create_schedule import CreateSchedule
from kingsec.application.use_cases.delete_schedule import DeleteSchedule
from kingsec.application.use_cases.disable_schedule import DisableSchedule
from kingsec.application.use_cases.enable_schedule import EnableSchedule
from kingsec.application.use_cases.find_due_schedules import FindDueSchedules
from kingsec.application.use_cases.get_schedule import GetSchedule
from kingsec.application.use_cases.list_schedules import ListSchedules
from kingsec.application.use_cases.pause_schedule import PauseSchedule
from kingsec.application.use_cases.resume_schedule import ResumeSchedule
from kingsec.application.use_cases.trigger_schedule_now import TriggerScheduleNow
from kingsec.application.use_cases.update_schedule import UpdateSchedule
from kingsec.bootstrap.application import Application
from kingsec.bootstrap.container import Container
from kingsec.domain import Role
from kingsec.domain.audit import AuditEntry
from kingsec.infrastructure.config import load_settings
from kingsec.infrastructure.rate_limit.system_clock import SystemClock
from kingsec.infrastructure.scheduler.in_process_scheduler import InProcessScheduler

from .test_session_api import TokenClaims


class InMemoryScheduleRepo(ScheduleRepositoryPort):
    def __init__(self) -> None:
        self._schedules: dict[str, Any] = {}

    def save(self, schedule: Any) -> None:
        self._schedules[str(schedule.id)] = schedule

    def find_by_id(self, schedule_id: str) -> Any | None:
        return self._schedules.get(schedule_id)

    def find_by_user_id(self, user_id: str) -> list[Any]:
        return [s for s in self._schedules.values() if s.owner_user_id == user_id]

    def find_all(self) -> list[Any]:
        return list(self._schedules.values())

    def find_due(self, now_utc_str: str) -> list[Any]:
        return [s for s in self._schedules.values() if s.is_due(now_utc_str)]

    def try_claim(self, schedule: Any) -> Any | None:
        current = self._schedules.get(str(schedule.id))
        if current is None or current.version != schedule.version:
            return None
        claimed = schedule.with_version(schedule.version + 1)
        self._schedules[str(schedule.id)] = claimed
        return claimed

    def delete(self, schedule_id: str) -> None:
        self._schedules.pop(schedule_id, None)


class ActorHolder:
    """Mutable holder for the currently-authenticated test user.

    KSEC-69-01: the owner/non-owner/admin matrix needs to swap identities
    mid-test (e.g. Alice creates a schedule, then Mallory calls the same
    endpoint) without rebuilding the app/TestClient. Since the FastAPI
    dependency override closes over this same object, mutating its fields
    changes who the *next* request is authenticated as.
    """

    def __init__(self, user_id: str = "u1", role: Role = Role.ADMIN) -> None:
        self.user_id = user_id
        self.role = role

    def as_current_user(self) -> CurrentUser:
        return CurrentUser(
            user_id=self.user_id,
            username=self.user_id,
            role=self.role,
            claims=TokenClaims(
                user_id=self.user_id,
                username=self.user_id,
                role=self.role.name.lower(),
                token_type="access",
                jti=f"{self.user_id}_jti",
                issued_at=None,
                expires_at=None,
            ),
        )


@pytest.fixture
def actor() -> ActorHolder:
    """Defaults to the original hardcoded identity (ADMIN "u1") so every
    pre-existing test in this file keeps working unmodified."""
    return ActorHolder(user_id="u1", role=Role.ADMIN)


@pytest.fixture
def app(actor: ActorHolder) -> FastAPI:
    container = Container()

    repo = InMemoryScheduleRepo()
    clock: ClockPort = SystemClock()
    job_service = InMemoryJobService()

    class FakeAudit(AuditPublisher):
        def __init__(self) -> None:
            self.entries: list[AuditEntry] = []

        def record(self, entry: AuditEntry) -> None:
            self.entries.append(entry)

    audit = FakeAudit()

    container.register_instance(ScheduleRepositoryPort, repo)
    container.register_instance(ClockPort, clock)
    container.register_instance(JobServicePort, job_service)
    container.register_instance(AuditPublisher, audit)

    class _NoOpScheduledAssessmentOrchestrator:
        """KSEC-98-01: this file exercises the schedule CRUD/trigger-now
        routes, never SchedulerServicePort's own poll behavior - only
        InProcessScheduler's constructor shape matters here."""

        def execute(self, schedule: Any) -> None:
            raise AssertionError("this test file never exercises _poll_due_schedules()")

    scheduler = InProcessScheduler(repo, _NoOpScheduledAssessmentOrchestrator(), clock)
    container.register_instance(SchedulerServicePort, scheduler)

    container.register_factory(
        CreateSchedule, lambda c: CreateSchedule(c.resolve(ScheduleRepositoryPort), c.resolve(AuditPublisher))
    )
    container.register_factory(
        UpdateSchedule, lambda c: UpdateSchedule(c.resolve(ScheduleRepositoryPort), c.resolve(AuditPublisher))
    )
    container.register_factory(
        DeleteSchedule, lambda c: DeleteSchedule(c.resolve(ScheduleRepositoryPort), c.resolve(AuditPublisher))
    )
    container.register_factory(ListSchedules, lambda c: ListSchedules(c.resolve(ScheduleRepositoryPort)))
    container.register_factory(GetSchedule, lambda c: GetSchedule(c.resolve(ScheduleRepositoryPort)))
    container.register_factory(
        PauseSchedule, lambda c: PauseSchedule(c.resolve(ScheduleRepositoryPort), c.resolve(AuditPublisher))
    )
    container.register_factory(
        ResumeSchedule, lambda c: ResumeSchedule(c.resolve(ScheduleRepositoryPort), c.resolve(AuditPublisher))
    )
    container.register_factory(
        EnableSchedule, lambda c: EnableSchedule(c.resolve(ScheduleRepositoryPort), c.resolve(AuditPublisher))
    )
    container.register_factory(
        DisableSchedule, lambda c: DisableSchedule(c.resolve(ScheduleRepositoryPort), c.resolve(AuditPublisher))
    )
    container.register_factory(
        TriggerScheduleNow,
        lambda c: TriggerScheduleNow(
            c.resolve(ScheduleRepositoryPort), c.resolve(JobServicePort), c.resolve(AuditPublisher)
        ),
    )
    container.register_factory(FindDueSchedules, lambda c: FindDueSchedules(c.resolve(ScheduleRepositoryPort)))

    settings = load_settings()
    application = Application(
        settings=settings,
        container=container,
        exception_handlers=None,
        logger=None,
        ensure_directories=False,
    )

    async def override_get_current_user() -> CurrentUser:
        return actor.as_current_user()

    fastapi_app = FastAPI()
    fastapi_app.state.kingsec_app = application
    fastapi_app.state.audit = audit
    fastapi_app.dependency_overrides[get_current_user] = override_get_current_user

    from kingsec.adapters.inbound.web.schedule_routes import router

    fastapi_app.include_router(router)
    register_error_handlers(fastapi_app)

    return fastapi_app


class TestScheduleAPI:
    def test_list_empty(self, app: FastAPI) -> None:
        client = TestClient(app)
        resp = client.get("/api/v1/schedules")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    def test_create(self, app: FastAPI) -> None:
        client = TestClient(app)
        resp = client.post(
            "/api/v1/schedules",
            json={"name": "Nightly Scan", "target": "10.0.0.1", "schedule_type": "daily", "timezone": "UTC"},
        )
        assert resp.status_code == 201
        data = resp.json()["schedule"]
        assert data["name"] == "Nightly Scan"
        assert data["target"] == "10.0.0.1"
        assert data["schedule_type"] == "daily"
        assert data["enabled"] is True

    def test_create_and_list(self, app: FastAPI) -> None:
        client = TestClient(app)
        client.post(
            "/api/v1/schedules",
            json={"name": "S1", "target": "10.0.0.1"},
        )
        client.post(
            "/api/v1/schedules",
            json={"name": "S2", "target": "10.0.0.2"},
        )
        resp = client.get("/api/v1/schedules")
        assert resp.status_code == 200
        assert len(resp.json()["items"]) == 2

    def test_get_schedule(self, app: FastAPI) -> None:
        client = TestClient(app)
        create_resp = client.post(
            "/api/v1/schedules",
            json={"name": "Get Me", "target": "10.0.0.1"},
        )
        sid = create_resp.json()["schedule"]["id"]

        resp = client.get(f"/api/v1/schedules/{sid}")
        assert resp.status_code == 200
        assert resp.json()["schedule"]["name"] == "Get Me"

    def test_update_schedule(self, app: FastAPI) -> None:
        client = TestClient(app)
        create_resp = client.post(
            "/api/v1/schedules",
            json={"name": "Old Name", "target": "10.0.0.1"},
        )
        sid = create_resp.json()["schedule"]["id"]

        resp = client.put(
            f"/api/v1/schedules/{sid}",
            json={"name": "New Name"},
        )
        assert resp.status_code == 200
        assert resp.json()["schedule"]["name"] == "New Name"

    def test_delete_schedule(self, app: FastAPI) -> None:
        client = TestClient(app)
        create_resp = client.post(
            "/api/v1/schedules",
            json={"name": "Delete Me", "target": "10.0.0.1"},
        )
        sid = create_resp.json()["schedule"]["id"]

        resp = client.delete(f"/api/v1/schedules/{sid}")
        assert resp.status_code == 200
        assert resp.json()["success"] is True

        resp2 = client.get("/api/v1/schedules")
        assert len(resp2.json()["items"]) == 0

    def test_pause_and_resume(self, app: FastAPI) -> None:
        client = TestClient(app)
        create_resp = client.post(
            "/api/v1/schedules",
            json={"name": "Pausable", "target": "10.0.0.1"},
        )
        sid = create_resp.json()["schedule"]["id"]

        pause_resp = client.post(f"/api/v1/schedules/{sid}/pause")
        assert pause_resp.status_code == 200
        assert pause_resp.json()["schedule"]["paused"] is True

        resume_resp = client.post(f"/api/v1/schedules/{sid}/resume")
        assert resume_resp.status_code == 200
        assert resume_resp.json()["schedule"]["paused"] is False

    def test_disable_and_enable(self, app: FastAPI) -> None:
        client = TestClient(app)
        create_resp = client.post(
            "/api/v1/schedules",
            json={"name": "Toggle", "target": "10.0.0.1"},
        )
        sid = create_resp.json()["schedule"]["id"]

        disable_resp = client.post(f"/api/v1/schedules/{sid}/disable")
        assert disable_resp.status_code == 200
        assert disable_resp.json()["schedule"]["enabled"] is False

        enable_resp = client.post(f"/api/v1/schedules/{sid}/enable")
        assert enable_resp.status_code == 200
        assert enable_resp.json()["schedule"]["enabled"] is True

    def test_trigger(self, app: FastAPI) -> None:
        client = TestClient(app)
        create_resp = client.post(
            "/api/v1/schedules",
            json={"name": "Triggerable", "target": "10.0.0.1"},
        )
        sid = create_resp.json()["schedule"]["id"]

        resp = client.post(f"/api/v1/schedules/{sid}/trigger")
        assert resp.status_code == 200
        data = resp.json()
        assert "job_id" in data
        assert data["schedule"]["name"] == "Triggerable"

    def test_due(self, app: FastAPI) -> None:
        client = TestClient(app)
        client.post(
            "/api/v1/schedules",
            json={"name": "Due Scan", "target": "10.0.0.1", "schedule_type": "daily"},
        )
        resp = client.get("/api/v1/schedules/due")
        assert resp.status_code == 200


class TestCreateScheduleBodyMaxLengthBoundary:
    """Phase 68 / Finding KSEC-64-04: CreateScheduleBody.schedule_type/
    .cron_expression/.timezone/.retry_strategy previously had no
    max_length - proves the constraint is enforced at the real HTTP
    boundary and that a rejected request never reaches CreateSchedule /
    the schedule store."""

    def test_over_limit_schedule_type_is_rejected_at_the_http_boundary(self, app: FastAPI) -> None:
        client = TestClient(app)
        resp = client.post(
            "/api/v1/schedules",
            json={"name": "oversized", "target": "10.0.0.1", "schedule_type": "x" * 33},
        )
        assert resp.status_code == 422, resp.text
        assert client.get("/api/v1/schedules").json()["items"] == []

    def test_over_limit_cron_expression_is_rejected_at_the_http_boundary(self, app: FastAPI) -> None:
        client = TestClient(app)
        resp = client.post(
            "/api/v1/schedules",
            json={"name": "oversized", "target": "10.0.0.1", "cron_expression": "x" * 257},
        )
        assert resp.status_code == 422, resp.text
        assert client.get("/api/v1/schedules").json()["items"] == []

    def test_over_limit_timezone_is_rejected_at_the_http_boundary(self, app: FastAPI) -> None:
        client = TestClient(app)
        resp = client.post(
            "/api/v1/schedules",
            json={"name": "oversized", "target": "10.0.0.1", "timezone": "x" * 65},
        )
        assert resp.status_code == 422, resp.text
        assert client.get("/api/v1/schedules").json()["items"] == []

    def test_over_limit_retry_strategy_is_rejected_at_the_http_boundary(self, app: FastAPI) -> None:
        client = TestClient(app)
        resp = client.post(
            "/api/v1/schedules",
            json={"name": "oversized", "target": "10.0.0.1", "retry_strategy": "x" * 33},
        )
        assert resp.status_code == 422, resp.text
        assert client.get("/api/v1/schedules").json()["items"] == []

    def test_exact_limit_timezone_is_accepted_and_stored(self, app: FastAPI) -> None:
        client = TestClient(app)
        resp = client.post(
            "/api/v1/schedules",
            json={"name": "exact-limit", "target": "10.0.0.1", "timezone": "x" * 64},
        )
        assert resp.status_code == 201, resp.text
        assert len(client.get("/api/v1/schedules").json()["items"]) == 1

    def test_over_limit_update_description_is_rejected_at_the_http_boundary(self, app: FastAPI) -> None:
        client = TestClient(app)
        create_resp = client.post(
            "/api/v1/schedules",
            json={"name": "To Update", "target": "10.0.0.1"},
        )
        sid = create_resp.json()["schedule"]["id"]

        resp = client.put(
            f"/api/v1/schedules/{sid}",
            json={"description": "x" * 1025},
        )
        assert resp.status_code == 422, resp.text

        # Downstream side effect did not occur: the schedule's
        # description was never updated.
        get_resp = client.get(f"/api/v1/schedules/{sid}")
        assert get_resp.json()["schedule"]["description"] == ""


class TestScheduleOwnershipAuthorization:
    """Phase 70 / KSEC-69-01: real-HTTP-route owner/non-owner/admin matrix.

    Alice owns the schedule under test throughout. Every operation is
    proven three ways: Alice (owner) succeeds, Mallory (unrelated
    ANALYST) is denied with no side effect and no audit entry, and Admin
    succeeds regardless of ownership.
    """

    def _create_as_alice(self, client: TestClient, actor: ActorHolder, name: str = "Alice's Schedule") -> str:
        actor.user_id = "alice"
        actor.role = Role.ANALYST
        resp = client.post("/api/v1/schedules", json={"name": name, "target": "10.99.99.99"})
        assert resp.status_code == 201, resp.text
        return str(resp.json()["schedule"]["id"])

    # ---- GET ----

    def test_get_owner_success(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        resp = client.get(f"/api/v1/schedules/{sid}")
        assert resp.status_code == 200
        assert resp.json()["schedule"]["name"] == "Alice's Schedule"

    def test_get_non_owner_denied(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        app.state.audit.entries.clear()

        actor.user_id = "mallory"
        actor.role = Role.ANALYST
        resp = client.get(f"/api/v1/schedules/{sid}")
        assert resp.status_code == 404
        assert app.state.audit.entries == []

    def test_get_admin_success(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)

        actor.user_id = "admin1"
        actor.role = Role.ADMIN
        resp = client.get(f"/api/v1/schedules/{sid}")
        assert resp.status_code == 200
        assert resp.json()["schedule"]["name"] == "Alice's Schedule"

    # ---- PUT (update) ----

    def test_update_owner_success(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        resp = client.put(f"/api/v1/schedules/{sid}", json={"name": "Renamed by Alice"})
        assert resp.status_code == 200
        assert resp.json()["schedule"]["name"] == "Renamed by Alice"

    def test_update_non_owner_denied(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        app.state.audit.entries.clear()

        actor.user_id = "mallory"
        actor.role = Role.ANALYST
        resp = client.put(f"/api/v1/schedules/{sid}", json={"name": "hijacked"})
        assert resp.status_code == 404
        assert app.state.audit.entries == []

        # No mutation: Alice still sees her original name.
        actor.user_id = "alice"
        actor.role = Role.ANALYST
        get_resp = client.get(f"/api/v1/schedules/{sid}")
        assert get_resp.json()["schedule"]["name"] == "Alice's Schedule"

    def test_update_admin_success(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)

        actor.user_id = "admin1"
        actor.role = Role.ADMIN
        resp = client.put(f"/api/v1/schedules/{sid}", json={"name": "Renamed by admin"})
        assert resp.status_code == 200
        assert resp.json()["schedule"]["name"] == "Renamed by admin"

    # ---- DELETE ----
    # KSEC-69-01 / deliberate deviation: DeleteSchedule's own pre-existing
    # "not found" shape is HTTP 200 {"success": false} (not a raised
    # exception / 404, unlike every sibling operation). The ownership
    # denial mirrors that exact pre-existing shape so a non-owner cannot
    # distinguish "doesn't exist" from "isn't yours" - it does NOT return
    # 404 here, and that is by design, not a shortfall.

    def test_delete_owner_success(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        resp = client.delete(f"/api/v1/schedules/{sid}")
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        assert client.get(f"/api/v1/schedules/{sid}").status_code == 404

    def test_delete_non_owner_denied(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        app.state.audit.entries.clear()

        actor.user_id = "mallory"
        actor.role = Role.ANALYST
        resp = client.delete(f"/api/v1/schedules/{sid}")
        assert resp.status_code == 200
        assert resp.json()["success"] is False
        assert app.state.audit.entries == []

        # No deletion: Alice's schedule still exists.
        actor.user_id = "alice"
        actor.role = Role.ANALYST
        assert client.get(f"/api/v1/schedules/{sid}").status_code == 200

    def test_delete_admin_success(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)

        actor.user_id = "admin1"
        actor.role = Role.ADMIN
        resp = client.delete(f"/api/v1/schedules/{sid}")
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    # ---- pause / resume ----

    def test_pause_owner_success(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        resp = client.post(f"/api/v1/schedules/{sid}/pause")
        assert resp.status_code == 200
        assert resp.json()["schedule"]["paused"] is True

    def test_pause_non_owner_denied(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        app.state.audit.entries.clear()

        actor.user_id = "mallory"
        actor.role = Role.ANALYST
        resp = client.post(f"/api/v1/schedules/{sid}/pause")
        assert resp.status_code == 404
        assert app.state.audit.entries == []

        actor.user_id = "alice"
        actor.role = Role.ANALYST
        assert client.get(f"/api/v1/schedules/{sid}").json()["schedule"]["paused"] is False

    def test_pause_admin_success(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)

        actor.user_id = "admin1"
        actor.role = Role.ADMIN
        resp = client.post(f"/api/v1/schedules/{sid}/pause")
        assert resp.status_code == 200
        assert resp.json()["schedule"]["paused"] is True

    def test_resume_owner_success(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        client.post(f"/api/v1/schedules/{sid}/pause")
        resp = client.post(f"/api/v1/schedules/{sid}/resume")
        assert resp.status_code == 200
        assert resp.json()["schedule"]["paused"] is False

    def test_resume_non_owner_denied(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        client.post(f"/api/v1/schedules/{sid}/pause")
        app.state.audit.entries.clear()

        actor.user_id = "mallory"
        actor.role = Role.ANALYST
        resp = client.post(f"/api/v1/schedules/{sid}/resume")
        assert resp.status_code == 404
        assert app.state.audit.entries == []

        actor.user_id = "alice"
        actor.role = Role.ANALYST
        assert client.get(f"/api/v1/schedules/{sid}").json()["schedule"]["paused"] is True

    def test_resume_admin_success(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        client.post(f"/api/v1/schedules/{sid}/pause")

        actor.user_id = "admin1"
        actor.role = Role.ADMIN
        resp = client.post(f"/api/v1/schedules/{sid}/resume")
        assert resp.status_code == 200
        assert resp.json()["schedule"]["paused"] is False

    # ---- enable / disable ----

    def test_disable_owner_success(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        resp = client.post(f"/api/v1/schedules/{sid}/disable")
        assert resp.status_code == 200
        assert resp.json()["schedule"]["enabled"] is False

    def test_disable_non_owner_denied(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        app.state.audit.entries.clear()

        actor.user_id = "mallory"
        actor.role = Role.ANALYST
        resp = client.post(f"/api/v1/schedules/{sid}/disable")
        assert resp.status_code == 404
        assert app.state.audit.entries == []

        actor.user_id = "alice"
        actor.role = Role.ANALYST
        assert client.get(f"/api/v1/schedules/{sid}").json()["schedule"]["enabled"] is True

    def test_disable_admin_success(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)

        actor.user_id = "admin1"
        actor.role = Role.ADMIN
        resp = client.post(f"/api/v1/schedules/{sid}/disable")
        assert resp.status_code == 200
        assert resp.json()["schedule"]["enabled"] is False

    def test_enable_owner_success(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        client.post(f"/api/v1/schedules/{sid}/disable")
        resp = client.post(f"/api/v1/schedules/{sid}/enable")
        assert resp.status_code == 200
        assert resp.json()["schedule"]["enabled"] is True

    def test_enable_non_owner_denied(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        client.post(f"/api/v1/schedules/{sid}/disable")
        app.state.audit.entries.clear()

        actor.user_id = "mallory"
        actor.role = Role.ANALYST
        resp = client.post(f"/api/v1/schedules/{sid}/enable")
        assert resp.status_code == 404
        assert app.state.audit.entries == []

        actor.user_id = "alice"
        actor.role = Role.ANALYST
        assert client.get(f"/api/v1/schedules/{sid}").json()["schedule"]["enabled"] is False

    def test_enable_admin_success(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        client.post(f"/api/v1/schedules/{sid}/disable")

        actor.user_id = "admin1"
        actor.role = Role.ADMIN
        resp = client.post(f"/api/v1/schedules/{sid}/enable")
        assert resp.status_code == 200
        assert resp.json()["schedule"]["enabled"] is True

    # ---- trigger ----

    def test_trigger_owner_success(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        resp = client.post(f"/api/v1/schedules/{sid}/trigger")
        assert resp.status_code == 200
        assert "job_id" in resp.json()

    def test_trigger_non_owner_denied(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)
        app.state.audit.entries.clear()

        actor.user_id = "mallory"
        actor.role = Role.ANALYST
        resp = client.post(f"/api/v1/schedules/{sid}/trigger")
        assert resp.status_code == 404
        assert app.state.audit.entries == []

    def test_trigger_admin_success(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)
        sid = self._create_as_alice(client, actor)

        actor.user_id = "admin1"
        actor.role = Role.ADMIN
        resp = client.post(f"/api/v1/schedules/{sid}/trigger")
        assert resp.status_code == 200
        assert "job_id" in resp.json()


class TestScheduleIdorRegression:
    """Phase 70 / Section 12: permanent regression test converting the
    Phase 69 discovery proof (prove_schedule_idor.py) into a real,
    committed end-to-end test - Alice creates a private schedule,
    Mallory (an unrelated authenticated ANALYST) attempts to read,
    modify, and delete it, and Admin retains full access throughout."""

    def test_alice_mallory_admin_end_to_end(self, app: FastAPI, actor: ActorHolder) -> None:
        client = TestClient(app)

        # [1] Alice creates a private, sensitive-looking schedule.
        actor.user_id = "alice"
        actor.role = Role.ANALYST
        create_resp = client.post(
            "/api/v1/schedules",
            json={"name": "alice-private-scan", "target": "10.99.99.99"},
        )
        assert create_resp.status_code == 201
        sid = create_resp.json()["schedule"]["id"]
        app.state.audit.entries.clear()

        # [2] Mallory, an unrelated authenticated user, targets Alice's
        # schedule by ID across every single-resource operation.
        actor.user_id = "mallory"
        actor.role = Role.ANALYST

        get_resp = client.get(f"/api/v1/schedules/{sid}")
        assert get_resp.status_code == 404

        put_resp = client.put(f"/api/v1/schedules/{sid}", json={"name": "hijacked", "target": "evil.example.com"})
        assert put_resp.status_code == 404

        pause_resp = client.post(f"/api/v1/schedules/{sid}/pause")
        assert pause_resp.status_code == 404

        resume_resp = client.post(f"/api/v1/schedules/{sid}/resume")
        assert resume_resp.status_code == 404

        disable_resp = client.post(f"/api/v1/schedules/{sid}/disable")
        assert disable_resp.status_code == 404

        enable_resp = client.post(f"/api/v1/schedules/{sid}/enable")
        assert enable_resp.status_code == 404

        trigger_resp = client.post(f"/api/v1/schedules/{sid}/trigger")
        assert trigger_resp.status_code == 404

        delete_resp = client.delete(f"/api/v1/schedules/{sid}")
        assert delete_resp.status_code == 200
        assert delete_resp.json()["success"] is False

        # None of Mallory's attempts produced an audit entry.
        assert app.state.audit.entries == []

        # [3] Alice's schedule is completely unaffected by any of it.
        actor.user_id = "alice"
        actor.role = Role.ANALYST
        alice_view = client.get(f"/api/v1/schedules/{sid}")
        assert alice_view.status_code == 200
        assert alice_view.json()["schedule"]["name"] == "alice-private-scan"
        assert alice_view.json()["schedule"]["target"] == "10.99.99.99"
        assert alice_view.json()["schedule"]["enabled"] is True
        assert alice_view.json()["schedule"]["paused"] is False

        # [4] Admin retains full access to Alice's schedule.
        actor.user_id = "admin1"
        actor.role = Role.ADMIN
        admin_view = client.get(f"/api/v1/schedules/{sid}")
        assert admin_view.status_code == 200
        assert admin_view.json()["schedule"]["name"] == "alice-private-scan"

        admin_delete = client.delete(f"/api/v1/schedules/{sid}")
        assert admin_delete.status_code == 200
        assert admin_delete.json()["success"] is True
