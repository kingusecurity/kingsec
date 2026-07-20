"""DTOs for scheduled scan use cases."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScheduleView:
    id: str
    name: str
    description: str
    owner_user_id: str
    target: str
    scanner_ids: list[str]
    config: dict[str, object]
    schedule_type: str
    cron_expression: str
    timezone: str
    enabled: bool
    paused: bool
    status: str
    created_at: str
    updated_at: str
    last_run: str | None = None
    next_run: str | None = None
    retry_strategy: str = "no_retry"
    max_retries: int = 0
    retry_delay_seconds: int = 0
    current_retry_count: int = 0


@dataclass(frozen=True)
class CreateScheduleRequest:
    name: str
    description: str = ""
    owner_user_id: str = ""
    target: str = ""
    scanner_ids: list[str] = field(default_factory=list)
    config: dict[str, object] = field(default_factory=dict)
    schedule_type: str = "one_time"
    cron_expression: str = ""
    timezone: str = "UTC"
    retry_strategy: str = "no_retry"
    max_retries: int = 0
    retry_delay_seconds: int = 0


@dataclass(frozen=True)
class CreateScheduleResponse:
    schedule: ScheduleView


@dataclass(frozen=True)
class UpdateScheduleRequest:
    schedule_id: str
    name: str | None = None
    description: str | None = None
    target: str | None = None
    scanner_ids: list[str] | None = None
    config: dict[str, object] | None = None
    schedule_type: str | None = None
    cron_expression: str | None = None
    timezone: str | None = None
    retry_strategy: str | None = None
    max_retries: int | None = None
    retry_delay_seconds: int | None = None


@dataclass(frozen=True)
class UpdateScheduleResponse:
    schedule: ScheduleView


@dataclass(frozen=True)
class DeleteScheduleRequest:
    schedule_id: str
    requesting_user_id: str = ""


@dataclass(frozen=True)
class DeleteScheduleResponse:
    success: bool


@dataclass(frozen=True)
class PauseScheduleRequest:
    schedule_id: str
    requesting_user_id: str = ""


@dataclass(frozen=True)
class PauseScheduleResponse:
    schedule: ScheduleView


@dataclass(frozen=True)
class ResumeScheduleRequest:
    schedule_id: str
    requesting_user_id: str = ""


@dataclass(frozen=True)
class ResumeScheduleResponse:
    schedule: ScheduleView


@dataclass(frozen=True)
class EnableScheduleRequest:
    schedule_id: str
    requesting_user_id: str = ""


@dataclass(frozen=True)
class EnableScheduleResponse:
    schedule: ScheduleView


@dataclass(frozen=True)
class DisableScheduleRequest:
    schedule_id: str
    requesting_user_id: str = ""


@dataclass(frozen=True)
class DisableScheduleResponse:
    schedule: ScheduleView


@dataclass(frozen=True)
class TriggerScheduleNowRequest:
    schedule_id: str
    requesting_user_id: str = ""


@dataclass(frozen=True)
class TriggerScheduleNowResponse:
    schedule: ScheduleView
    job_id: str


@dataclass(frozen=True)
class ListSchedulesRequest:
    requesting_user_id: str = ""
    is_admin: bool = False


@dataclass(frozen=True)
class ListSchedulesResponse:
    schedules: list[ScheduleView] = field(default_factory=list)


@dataclass(frozen=True)
class GetScheduleRequest:
    schedule_id: str
    requesting_user_id: str = ""


@dataclass(frozen=True)
class GetScheduleResponse:
    schedule: ScheduleView
