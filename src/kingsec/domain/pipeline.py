from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class PipelineState(StrEnum):
    QUEUED = "queued"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COLLECTING_RESULTS = "collecting_results"
    GENERATING_REPORT = "generating_report"
    SENDING_NOTIFICATION = "sending_notification"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


PIPELINE_ORDER: list[PipelineState] = [
    PipelineState.QUEUED,
    PipelineState.ASSIGNED,
    PipelineState.RUNNING,
    PipelineState.COLLECTING_RESULTS,
    PipelineState.GENERATING_REPORT,
    PipelineState.SENDING_NOTIFICATION,
    PipelineState.COMPLETED,
]


@dataclass(frozen=True)
class PipelineId:
    value: str

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class PipelineStage:
    name: str
    status: str = "pending"
    started_at: str = ""
    completed_at: str = ""
    error_message: str = ""


@dataclass(frozen=True)
class PipelineResult:
    job_id: str = ""
    queue_entry_id: str = ""
    agent_id: str = ""
    report_id: str = ""
    notification_ids: tuple[str, ...] = ()
    findings_count: int = 0
    summary: str = ""
    error_message: str = ""
    started_at: str = ""
    completed_at: str = ""


@dataclass(frozen=True)
class PipelineExecution:
    pipeline_id: PipelineId
    target: str
    state: PipelineState
    stages: tuple[PipelineStage, ...] = ()
    result: PipelineResult = field(default_factory=PipelineResult)
    owner_user_id: str = ""
    scanner_ids: tuple[str, ...] = ()
    priority: str = "normal"
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
