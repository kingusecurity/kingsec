"""Tests for scheduled scan use cases."""

from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.ports.job_service import JobServicePort
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
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
from kingsec.application.use_cases.schedule_dto import (
    CreateScheduleRequest,
    DeleteScheduleRequest,
    DisableScheduleRequest,
    EnableScheduleRequest,
    GetScheduleRequest,
    ListSchedulesRequest,
    PauseScheduleRequest,
    ResumeScheduleRequest,
    TriggerScheduleNowRequest,
    UpdateScheduleRequest,
)
from kingsec.application.use_cases.trigger_schedule_now import TriggerScheduleNow
from kingsec.application.use_cases.update_schedule import UpdateSchedule
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.application.job import JobId
from kingsec.domain.schedule import (
    ScheduleId,
    ScheduleStatus,
    ScheduleType,
    ScanSchedule,
)
from kingsec.application.jobs import ScanJob, JobStatus


class InMemoryScheduleRepo(ScheduleRepositoryPort):
    def __init__(self) -> None:
        self._schedules: dict[str, ScanSchedule] = {}

    def save(self, schedule: ScanSchedule) -> None:
        self._schedules[str(schedule.id)] = schedule

    def find_by_id(self, schedule_id: str) -> ScanSchedule | None:
        return self._schedules.get(schedule_id)

    def find_by_user_id(self, user_id: str) -> list[ScanSchedule]:
        return [s for s in self._schedules.values() if s.owner_user_id == user_id]

    def find_all(self) -> list[ScanSchedule]:
        return list(self._schedules.values())

    def find_due(self, now_utc_str: str) -> list[ScanSchedule]:
        return [s for s in self._schedules.values() if s.is_due(now_utc_str)]

    def delete(self, schedule_id: str) -> None:
        self._schedules.pop(schedule_id, None)


class FakeAuditPublisher(AuditPublisher):
    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        self.entries.append(entry)


class FakeJobService(JobServicePort):
    def __init__(self) -> None:
        self.jobs: list[ScanJob] = []

    def submit_scan(self, target: str, config: dict | None = None) -> ScanJob:
        job = ScanJob(
            id=JobId(value=f"job-{len(self.jobs)}"),
            target=target,
            config=config or {},
            status=JobStatus.PENDING,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        self.jobs.append(job)
        return job

    def get_job(self, job_id: str) -> ScanJob:
        raise NotImplementedError

    def list_jobs(self) -> list[ScanJob]:
        return self.jobs

    def cancel_job(self, job_id: str) -> ScanJob:
        raise NotImplementedError

    def transition_job(self, job_id: str, target_status: str) -> ScanJob:
        raise NotImplementedError

    def find_oldest_pending(self) -> ScanJob | None:
        pending = [j for j in self.jobs if j.status == JobStatus.PENDING]
        if not pending:
            return None
        return min(pending, key=lambda j: j.created_at)

    def get_job_result(self, job_id: str) -> object:
        raise NotImplementedError


class TestCreateSchedule:
    def test_create(self) -> None:
        repo = InMemoryScheduleRepo()
        audit = FakeAuditPublisher()
        uc = CreateSchedule(repo, audit)
        result = uc.execute(
            CreateScheduleRequest(name="Nightly", target="10.0.0.1", owner_user_id="u1")
        )
        assert result.schedule.name == "Nightly"
        assert result.schedule.target == "10.0.0.1"
        assert result.schedule.enabled is True
        assert result.schedule.schedule_type == "one_time"
        assert len(audit.entries) == 1
        assert audit.entries[0].action == AuditAction.SCHEDULE_CREATED


class TestUpdateSchedule:
    def test_update_name(self) -> None:
        repo = InMemoryScheduleRepo()
        audit = FakeAuditPublisher()
        create_uc = CreateSchedule(repo, audit)
        create_uc.execute(
            CreateScheduleRequest(name="Old Name", target="10.0.0.1", owner_user_id="u1")
        )
        sid = list(repo._schedules.keys())[0]

        update_uc = UpdateSchedule(repo, audit)
        result = update_uc.execute(
            UpdateScheduleRequest(schedule_id=sid, name="New Name")
        )
        assert result.schedule.name == "New Name"

    def test_update_not_found(self) -> None:
        repo = InMemoryScheduleRepo()
        audit = FakeAuditPublisher()
        uc = UpdateSchedule(repo, audit)
        try:
            uc.execute(UpdateScheduleRequest(schedule_id="nonexistent"))
            assert False, "should raise"
        except Exception:
            pass


class TestDeleteSchedule:
    def test_delete_existing(self) -> None:
        repo = InMemoryScheduleRepo()
        audit = FakeAuditPublisher()
        create_uc = CreateSchedule(repo, audit)
        create_uc.execute(CreateScheduleRequest(name="Del", target="10.0.0.1", owner_user_id="u1"))
        sid = list(repo._schedules.keys())[0]

        delete_uc = DeleteSchedule(repo, audit)
        result = delete_uc.execute(DeleteScheduleRequest(schedule_id=sid))
        assert result.success
        assert repo.find_by_id(sid) is None
        assert audit.entries[1].action == AuditAction.SCHEDULE_DELETED

    def test_delete_missing(self) -> None:
        repo = InMemoryScheduleRepo()
        audit = FakeAuditPublisher()
        uc = DeleteSchedule(repo, audit)
        result = uc.execute(DeleteScheduleRequest(schedule_id="nonexistent"))
        assert not result.success


class TestPauseSchedule:
    def test_pause(self) -> None:
        repo = InMemoryScheduleRepo()
        audit = FakeAuditPublisher()
        create_uc = CreateSchedule(repo, audit)
        create_uc.execute(CreateScheduleRequest(name="Pausable", target="10.0.0.1", owner_user_id="u1"))
        sid = list(repo._schedules.keys())[0]

        uc = PauseSchedule(repo, audit)
        result = uc.execute(PauseScheduleRequest(schedule_id=sid))
        assert result.schedule.paused is True
        assert result.schedule.status == "paused"
        assert audit.entries[1].action == AuditAction.SCHEDULE_PAUSED


class TestResumeSchedule:
    def test_resume(self) -> None:
        repo = InMemoryScheduleRepo()
        audit = FakeAuditPublisher()
        create_uc = CreateSchedule(repo, audit)
        create_uc.execute(CreateScheduleRequest(name="Resumable", target="10.0.0.1", owner_user_id="u1"))
        sid = list(repo._schedules.keys())[0]

        pause_uc = PauseSchedule(repo, audit)
        pause_uc.execute(PauseScheduleRequest(schedule_id=sid))

        resume_uc = ResumeSchedule(repo, audit)
        result = resume_uc.execute(ResumeScheduleRequest(schedule_id=sid))
        assert result.schedule.paused is False
        assert result.schedule.status == "active"


class TestEnableDisable:
    def test_disable_and_enable(self) -> None:
        repo = InMemoryScheduleRepo()
        audit = FakeAuditPublisher()
        create_uc = CreateSchedule(repo, audit)
        create_uc.execute(CreateScheduleRequest(name="Toggle", target="10.0.0.1", owner_user_id="u1"))
        sid = list(repo._schedules.keys())[0]

        disable_uc = DisableSchedule(repo, audit)
        dresult = disable_uc.execute(DisableScheduleRequest(schedule_id=sid))
        assert dresult.schedule.enabled is False
        assert dresult.schedule.status == "disabled"

        enable_uc = EnableSchedule(repo, audit)
        eresult = enable_uc.execute(EnableScheduleRequest(schedule_id=sid))
        assert eresult.schedule.enabled is True
        assert eresult.schedule.status == "active"


class TestTriggerScheduleNow:
    def test_trigger(self) -> None:
        repo = InMemoryScheduleRepo()
        audit = FakeAuditPublisher()
        job_svc = FakeJobService()
        create_uc = CreateSchedule(repo, audit)
        create_uc.execute(CreateScheduleRequest(name="Triggerable", target="10.0.0.1", owner_user_id="u1"))
        sid = list(repo._schedules.keys())[0]

        uc = TriggerScheduleNow(repo, job_svc, audit)
        result = uc.execute(TriggerScheduleNowRequest(schedule_id=sid))
        assert result.job_id.startswith("job-")
        assert len(job_svc.jobs) == 1

    def test_trigger_not_found(self) -> None:
        repo = InMemoryScheduleRepo()
        audit = FakeAuditPublisher()
        job_svc = FakeJobService()
        uc = TriggerScheduleNow(repo, job_svc, audit)
        try:
            uc.execute(TriggerScheduleNowRequest(schedule_id="nonexistent"))
            assert False, "should raise"
        except Exception:
            pass


class TestListSchedules:
    def test_list_own(self) -> None:
        repo = InMemoryScheduleRepo()
        audit = FakeAuditPublisher()
        create_uc = CreateSchedule(repo, audit)
        create_uc.execute(CreateScheduleRequest(name="S1", target="10.0.0.1", owner_user_id="u1"))
        create_uc.execute(CreateScheduleRequest(name="S2", target="10.0.0.2", owner_user_id="u2"))

        uc = ListSchedules(repo)
        result = uc.execute(ListSchedulesRequest(requesting_user_id="u1"))
        assert len(result.schedules) == 1
        assert result.schedules[0].name == "S1"

    def test_list_all_admin(self) -> None:
        repo = InMemoryScheduleRepo()
        audit = FakeAuditPublisher()
        create_uc = CreateSchedule(repo, audit)
        create_uc.execute(CreateScheduleRequest(name="S1", target="10.0.0.1", owner_user_id="u1"))
        create_uc.execute(CreateScheduleRequest(name="S2", target="10.0.0.2", owner_user_id="u2"))

        uc = ListSchedules(repo)
        result = uc.execute(ListSchedulesRequest(is_admin=True))
        assert len(result.schedules) == 2


class TestGetSchedule:
    def test_get(self) -> None:
        repo = InMemoryScheduleRepo()
        audit = FakeAuditPublisher()
        create_uc = CreateSchedule(repo, audit)
        create_uc.execute(CreateScheduleRequest(name="Test", target="10.0.0.1", owner_user_id="u1"))
        sid = list(repo._schedules.keys())[0]

        uc = GetSchedule(repo)
        result = uc.execute(GetScheduleRequest(schedule_id=sid))
        assert result.schedule.name == "Test"

    def test_get_not_found(self) -> None:
        repo = InMemoryScheduleRepo()
        uc = GetSchedule(repo)
        try:
            uc.execute(GetScheduleRequest(schedule_id="nonexistent"))
            assert False, "should raise"
        except Exception:
            pass


class TestFindDueSchedules:
    def test_find_due(self) -> None:
        repo = InMemoryScheduleRepo()
        audit = FakeAuditPublisher()
        create_uc = CreateSchedule(repo, audit)
        create_uc.execute(CreateScheduleRequest(name="Due", target="10.0.0.1", owner_user_id="u1"))

        # Manually set next_run in the past
        sid = list(repo._schedules.keys())[0]
        existing = repo._schedules[sid]
        repo._schedules[sid] = ScanSchedule(
            id=existing.id, name=existing.name, description=existing.description,
            owner_user_id=existing.owner_user_id, target=existing.target,
            scanner_ids=existing.scanner_ids, config=existing.config,
            schedule_type=existing.schedule_type, cron_expression=existing.cron_expression,
            timezone=existing.timezone, enabled=existing.enabled, paused=existing.paused,
            created_at=existing.created_at, updated_at=existing.updated_at,
            last_run=existing.last_run, next_run="2020-01-01T00:00:00",
            retry_policy=existing.retry_policy, current_retry_count=existing.current_retry_count,
            status=existing.status,
        )

        uc = FindDueSchedules(repo)
        result = uc.execute()
        assert len(result.schedules) == 1
        assert result.schedules[0].name == "Due"
