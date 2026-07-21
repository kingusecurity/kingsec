"""Tests for schedule domain entities."""

from __future__ import annotations

from kingsec.domain.schedule import (
    RetryPolicy,
    RetryStrategy,
    ScanSchedule,
    ScheduleId,
    ScheduleStatus,
    ScheduleType,
)


class TestScheduleType:
    def test_values(self) -> None:
        assert ScheduleType.ONE_TIME.value == "one_time"
        assert ScheduleType.HOURLY.value == "hourly"
        assert ScheduleType.DAILY.value == "daily"
        assert ScheduleType.WEEKLY.value == "weekly"
        assert ScheduleType.MONTHLY.value == "monthly"
        assert ScheduleType.CRON.value == "cron"


class TestScheduleStatus:
    def test_values(self) -> None:
        assert ScheduleStatus.ACTIVE.value == "active"
        assert ScheduleStatus.PAUSED.value == "paused"
        assert ScheduleStatus.DISABLED.value == "disabled"
        assert ScheduleStatus.COMPLETED.value == "completed"
        assert ScheduleStatus.FAILED.value == "failed"


class TestRetryStrategy:
    def test_values(self) -> None:
        assert RetryStrategy.NO_RETRY.value == "no_retry"
        assert RetryStrategy.FIXED.value == "fixed"


class TestScheduleId:
    def test_creation(self) -> None:
        sid = ScheduleId(value="schedule-1")
        assert str(sid) == "schedule-1"

    def test_frozen(self) -> None:
        sid = ScheduleId(value="fixed")
        try:
            sid.value = "changed"  # type: ignore[misc]
            assert False, "should be frozen"
        except AttributeError:
            pass


class TestRetryPolicy:
    def test_defaults(self) -> None:
        rp = RetryPolicy()
        assert rp.strategy == RetryStrategy.NO_RETRY
        assert rp.max_retries == 0
        assert rp.retry_delay_seconds == 0

    def test_custom(self) -> None:
        rp = RetryPolicy(strategy=RetryStrategy.FIXED, max_retries=3, retry_delay_seconds=300)
        assert rp.strategy == RetryStrategy.FIXED
        assert rp.max_retries == 3
        assert rp.retry_delay_seconds == 300

    def test_frozen(self) -> None:
        rp = RetryPolicy()
        try:
            rp.max_retries = 5  # type: ignore[misc]
            assert False, "should be frozen"
        except AttributeError:
            pass


class TestScanSchedule:
    def _make_schedule(self, **overrides: object) -> ScanSchedule:
        fields = {
            "id": ScheduleId(value="sched-1"),
            "name": "Test Scan",
            "description": "A test schedule",
            "owner_user_id": "user-1",
            "target": "10.0.0.1",
            "scanner_ids": ("nmap", "nikto"),
            "config": {"ports": "80,443"},
            "schedule_type": ScheduleType.DAILY,
            "cron_expression": "",
            "timezone": "UTC",
            "enabled": True,
            "paused": False,
            "created_at": "2025-01-01T00:00:00",
            "updated_at": "2025-01-01T00:00:00",
        }
        fields.update(**overrides)
        return ScanSchedule(**fields)

    def test_creation(self) -> None:
        s = self._make_schedule()
        assert str(s.id) == "sched-1"
        assert s.name == "Test Scan"
        assert s.target == "10.0.0.1"
        assert s.schedule_type == ScheduleType.DAILY
        assert s.enabled is True
        assert s.paused is False
        assert s.status == ScheduleStatus.ACTIVE

    def test_is_due_no_next_run(self) -> None:
        s = self._make_schedule(next_run=None)
        assert s.is_due("2025-01-02T00:00:00") is True

    def test_is_due_disabled(self) -> None:
        s = self._make_schedule(enabled=False, next_run="2025-01-01T00:00:00")
        assert s.is_due("2025-01-02T00:00:00") is False

    def test_is_due_paused(self) -> None:
        s = self._make_schedule(paused=True, next_run="2025-01-01T00:00:00")
        assert s.is_due("2025-01-02T00:00:00") is False

    def test_is_due_future(self) -> None:
        s = self._make_schedule(next_run="2025-01-10T00:00:00")
        assert s.is_due("2025-01-05T00:00:00") is False

    def test_is_due_past(self) -> None:
        s = self._make_schedule(next_run="2025-01-01T00:00:00")
        assert s.is_due("2025-01-05T00:00:00") is True

    def test_with_status(self) -> None:
        s = self._make_schedule()
        updated = s.with_status(ScheduleStatus.PAUSED)
        assert updated.status == ScheduleStatus.PAUSED
        assert s.status == ScheduleStatus.ACTIVE

    def test_with_next_run(self) -> None:
        s = self._make_schedule()
        updated = s.with_next_run("2025-02-01T00:00:00")
        assert updated.next_run == "2025-02-01T00:00:00"
        assert s.next_run is None

    def test_with_run_completed(self) -> None:
        s = self._make_schedule(last_run=None, next_run="2025-01-01T00:00:00")
        updated = s.with_run_completed(next_run="2025-01-02T00:00:00", now="2025-01-01T12:00:00")
        assert updated.last_run == "2025-01-01T12:00:00"
        assert updated.next_run == "2025-01-02T00:00:00"
        assert updated.current_retry_count == 0
