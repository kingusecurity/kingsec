"""Pydantic schemas for the scheduled scan API."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ScheduleViewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

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


class ListSchedulesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ScheduleViewResponse]


class CreateScheduleBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=256)
    description: str = Field(default="", max_length=1024)
    target: str = Field(..., min_length=1, max_length=2048)
    scanner_ids: list[str] = Field(default_factory=list)
    config: dict[str, object] = Field(default_factory=dict)
    # 32: ScheduleType's longest defined value is 8 characters
    # ("one_time") - generous margin for future values.
    schedule_type: str = Field(default="one_time", max_length=32)
    # 256: standard cron syntax (5-6 whitespace-separated fields) is far
    # shorter than this even with lists/ranges; no domain limit exists,
    # so this is a conservative, generous bound.
    cron_expression: str = Field(default="", max_length=256)
    # 64: the longest real IANA timezone names (e.g.
    # "America/Argentina/ComodRivadavia") are ~33 characters.
    timezone: str = Field(default="UTC", max_length=64)
    # 32: RetryStrategy's longest defined value is 8 characters
    # ("no_retry") - generous margin for future values.
    retry_strategy: str = Field(default="no_retry", max_length=32)
    max_retries: int = Field(default=0, ge=0)
    retry_delay_seconds: int = Field(default=0, ge=0)


class CreateScheduleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schedule: ScheduleViewResponse


class UpdateScheduleBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=256)
    # Bounds mirror CreateScheduleBody's equivalent fields exactly - the
    # same conceptual fields must not disagree between create and update.
    description: str | None = Field(default=None, max_length=1024)
    target: str | None = Field(default=None, min_length=1, max_length=2048)
    scanner_ids: list[str] | None = None
    config: dict[str, object] | None = None
    schedule_type: str | None = Field(default=None, max_length=32)
    cron_expression: str | None = Field(default=None, max_length=256)
    timezone: str | None = Field(default=None, max_length=64)
    retry_strategy: str | None = Field(default=None, max_length=32)
    max_retries: int | None = None
    retry_delay_seconds: int | None = None


class UpdateScheduleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schedule: ScheduleViewResponse


class TriggerScheduleNowResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schedule: ScheduleViewResponse
    job_id: str


class PauseScheduleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schedule: ScheduleViewResponse


class ResumeScheduleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schedule: ScheduleViewResponse


class EnableScheduleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schedule: ScheduleViewResponse


class DisableScheduleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schedule: ScheduleViewResponse


class DeleteScheduleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    success: bool
