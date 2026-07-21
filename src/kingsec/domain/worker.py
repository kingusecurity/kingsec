"""Worker domain — immutable value objects for the worker engine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class WorkerStatus(StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass(frozen=True)
class WorkerId:
    value: str

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class WorkerHeartbeat:
    worker_id: WorkerId
    status: WorkerStatus
    timestamp: str
    current_job_id: str | None = None
    jobs_completed: int = 0
    jobs_failed: int = 0
    error_message: str | None = None


@dataclass(frozen=True)
class WorkerConfiguration:
    poll_interval_seconds: int = 30
    max_concurrent_jobs: int = 1
    job_timeout_seconds: int = 3600
