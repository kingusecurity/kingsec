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

    def delete(self, schedule_id: str) -> None:
        self._schedules.pop(schedule_id, None)


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
            jti="admin_jti",
            issued_at=None,
            expires_at=None,
        ),
    )


@pytest.fixture
def app() -> FastAPI:
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

    scheduler = InProcessScheduler(repo, job_service, clock)
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

    fastapi_app = FastAPI()
    fastapi_app.state.kingsec_app = application
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
