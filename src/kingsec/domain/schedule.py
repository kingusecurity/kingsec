"""Scheduled scan domain — immutable value objects and entities."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ScheduleType(StrEnum):
    ONE_TIME = "one_time"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CRON = "cron"


class ScheduleStatus(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"
    COMPLETED = "completed"
    FAILED = "failed"


class RetryStrategy(StrEnum):
    NO_RETRY = "no_retry"
    FIXED = "fixed"


@dataclass(frozen=True)
class ScheduleId:
    value: str

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class RetryPolicy:
    strategy: RetryStrategy = RetryStrategy.NO_RETRY
    max_retries: int = 0
    retry_delay_seconds: int = 0


@dataclass(frozen=True)
class ScanSchedule:
    id: ScheduleId
    name: str
    description: str
    owner_user_id: str
    target: str
    scanner_ids: tuple[str, ...]
    config: dict[str, object]
    schedule_type: ScheduleType
    cron_expression: str
    timezone: str
    enabled: bool
    paused: bool
    created_at: str
    updated_at: str
    last_run: str | None = None
    next_run: str | None = None
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    current_retry_count: int = 0
    status: ScheduleStatus = ScheduleStatus.ACTIVE

    def is_due(self, now_utc_str: str) -> bool:
        if not self.enabled or self.paused:
            return False
        if self.next_run is None:
            return True
        return now_utc_str >= self.next_run

    def with_next_run(self, next_run: str | None) -> ScanSchedule:
        return ScanSchedule(
            id=self.id, name=self.name, description=self.description,
            owner_user_id=self.owner_user_id, target=self.target,
            scanner_ids=self.scanner_ids, config=self.config,
            schedule_type=self.schedule_type, cron_expression=self.cron_expression,
            timezone=self.timezone, enabled=self.enabled, paused=self.paused,
            created_at=self.created_at, updated_at=self.updated_at,
            last_run=self.last_run, next_run=next_run,
            retry_policy=self.retry_policy, current_retry_count=self.current_retry_count,
            status=self.status,
        )

    def with_status(self, status: ScheduleStatus) -> ScanSchedule:
        return ScanSchedule(
            id=self.id, name=self.name, description=self.description,
            owner_user_id=self.owner_user_id, target=self.target,
            scanner_ids=self.scanner_ids, config=self.config,
            schedule_type=self.schedule_type, cron_expression=self.cron_expression,
            timezone=self.timezone, enabled=self.enabled, paused=self.paused,
            created_at=self.created_at, updated_at=self.updated_at,
            last_run=self.last_run, next_run=self.next_run,
            retry_policy=self.retry_policy, current_retry_count=self.current_retry_count,
            status=status,
        )

    def with_run_completed(self, next_run: str | None, now: str) -> ScanSchedule:
        return ScanSchedule(
            id=self.id, name=self.name, description=self.description,
            owner_user_id=self.owner_user_id, target=self.target,
            scanner_ids=self.scanner_ids, config=self.config,
            schedule_type=self.schedule_type, cron_expression=self.cron_expression,
            timezone=self.timezone, enabled=self.enabled, paused=self.paused,
            created_at=self.created_at, updated_at=now,
            last_run=now, next_run=next_run,
            retry_policy=self.retry_policy, current_retry_count=0,
            status=self.status,
        )
