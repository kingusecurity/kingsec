"""Distributed job domain — job state machine and lease value objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class JobState(StrEnum):
    QUEUED = "queued"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"
    EXPIRED = "expired"


@dataclass(frozen=True)
class JobQueueEntry:
    entry_id: str
    job_id: str
    state: JobState
    payload: str = ""
    target: str = ""
    scanner_ids: tuple[str, ...] = ()
    assigned_worker_id: str | None = None
    retry_count: int = 0
    max_retries: int = 3
    error_message: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    started_at: str | None = None
    completed_at: str | None = None

    def assign(self, worker_id: str) -> JobQueueEntry:
        return JobQueueEntry(
            entry_id=self.entry_id,
            job_id=self.job_id,
            state=JobState.ASSIGNED,
            payload=self.payload,
            target=self.target,
            scanner_ids=self.scanner_ids,
            assigned_worker_id=worker_id,
            retry_count=self.retry_count,
            max_retries=self.max_retries,
            created_at=self.created_at,
            updated_at=datetime.now(UTC).isoformat(),
            started_at=datetime.now(UTC).isoformat(),
        )

    def mark_running(self) -> JobQueueEntry:
        return JobQueueEntry(
            entry_id=self.entry_id,
            job_id=self.job_id,
            state=JobState.RUNNING,
            payload=self.payload,
            target=self.target,
            scanner_ids=self.scanner_ids,
            assigned_worker_id=self.assigned_worker_id,
            retry_count=self.retry_count,
            max_retries=self.max_retries,
            created_at=self.created_at,
            updated_at=datetime.now(UTC).isoformat(),
            started_at=self.started_at or datetime.now(UTC).isoformat(),
        )

    def mark_completed(self) -> JobQueueEntry:
        return JobQueueEntry(
            entry_id=self.entry_id,
            job_id=self.job_id,
            state=JobState.COMPLETED,
            payload=self.payload,
            target=self.target,
            scanner_ids=self.scanner_ids,
            assigned_worker_id=self.assigned_worker_id,
            retry_count=self.retry_count,
            max_retries=self.max_retries,
            created_at=self.created_at,
            updated_at=datetime.now(UTC).isoformat(),
            started_at=self.started_at,
            completed_at=datetime.now(UTC).isoformat(),
        )

    def mark_failed(self, error: str = "") -> JobQueueEntry:
        return JobQueueEntry(
            entry_id=self.entry_id,
            job_id=self.job_id,
            state=JobState.FAILED,
            payload=self.payload,
            target=self.target,
            scanner_ids=self.scanner_ids,
            assigned_worker_id=self.assigned_worker_id,
            retry_count=self.retry_count,
            max_retries=self.max_retries,
            error_message=error,
            created_at=self.created_at,
            updated_at=datetime.now(UTC).isoformat(),
            started_at=self.started_at,
            completed_at=datetime.now(UTC).isoformat(),
        )

    def mark_retrying(self) -> JobQueueEntry:
        return JobQueueEntry(
            entry_id=self.entry_id,
            job_id=self.job_id,
            state=JobState.RETRYING,
            payload=self.payload,
            target=self.target,
            scanner_ids=self.scanner_ids,
            assigned_worker_id=None,
            retry_count=self.retry_count + 1,
            max_retries=self.max_retries,
            created_at=self.created_at,
            updated_at=datetime.now(UTC).isoformat(),
        )

    def mark_cancelled(self) -> JobQueueEntry:
        return JobQueueEntry(
            entry_id=self.entry_id,
            job_id=self.job_id,
            state=JobState.CANCELLED,
            payload=self.payload,
            target=self.target,
            scanner_ids=self.scanner_ids,
            assigned_worker_id=self.assigned_worker_id,
            retry_count=self.retry_count,
            max_retries=self.max_retries,
            created_at=self.created_at,
            updated_at=datetime.now(UTC).isoformat(),
            completed_at=datetime.now(UTC).isoformat(),
        )

    def mark_expired(self) -> JobQueueEntry:
        return JobQueueEntry(
            entry_id=self.entry_id,
            job_id=self.job_id,
            state=JobState.EXPIRED,
            payload=self.payload,
            target=self.target,
            scanner_ids=self.scanner_ids,
            assigned_worker_id=self.assigned_worker_id,
            retry_count=self.retry_count,
            max_retries=self.max_retries,
            error_message="Job lease expired",
            created_at=self.created_at,
            updated_at=datetime.now(UTC).isoformat(),
            completed_at=datetime.now(UTC).isoformat(),
        )


@dataclass(frozen=True)
class JobLease:
    lease_id: str
    job_id: str
    worker_id: str
    acquired_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    expires_at: str = ""
    renewed_at: str = ""
    released_at: str | None = None

    def is_expired(self, now: str | None = None) -> bool:
        now = now or datetime.now(UTC).isoformat()
        return now > self.expires_at if self.expires_at else False

    def renew(self, ttl_seconds: int = 120) -> JobLease:
        return JobLease(
            lease_id=self.lease_id,
            job_id=self.job_id,
            worker_id=self.worker_id,
            acquired_at=self.acquired_at,
            expires_at=datetime.now(UTC).isoformat(),
            renewed_at=datetime.now(UTC).isoformat(),
        )

    def release(self) -> JobLease:
        return JobLease(
            lease_id=self.lease_id,
            job_id=self.job_id,
            worker_id=self.worker_id,
            acquired_at=self.acquired_at,
            expires_at=self.expires_at,
            renewed_at=self.renewed_at,
            released_at=datetime.now(UTC).isoformat(),
        )


class WorkerStatus(StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    DEGRADED = "degraded"


@dataclass(frozen=True)
class WorkerCapability:
    scanner_id: str
    scanner_name: str
    scanner_version: str


@dataclass(frozen=True)
class WorkerNode:
    worker_id: str
    hostname: str
    os: str
    cpu: str
    ram_mb: int
    capabilities: tuple[WorkerCapability, ...] = ()
    current_jobs: tuple[str, ...] = ()
    health: str = "healthy"
    last_heartbeat: str = ""
    status: WorkerStatus = WorkerStatus.ONLINE
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def update_heartbeat(self, status: WorkerStatus = WorkerStatus.ONLINE, current_jobs: tuple[str, ...] = (), health: str = "healthy") -> WorkerNode:
        return WorkerNode(
            worker_id=self.worker_id,
            hostname=self.hostname,
            os=self.os,
            cpu=self.cpu,
            ram_mb=self.ram_mb,
            capabilities=self.capabilities,
            current_jobs=current_jobs,
            health=health,
            last_heartbeat=datetime.now(UTC).isoformat(),
            status=status,
            created_at=self.created_at,
            updated_at=datetime.now(UTC).isoformat(),
        )

    def mark_offline(self) -> WorkerNode:
        return WorkerNode(
            worker_id=self.worker_id,
            hostname=self.hostname,
            os=self.os,
            cpu=self.cpu,
            ram_mb=self.ram_mb,
            capabilities=self.capabilities,
            current_jobs=self.current_jobs,
            health=self.health,
            last_heartbeat=self.last_heartbeat,
            status=WorkerStatus.OFFLINE,
            created_at=self.created_at,
            updated_at=datetime.now(UTC).isoformat(),
        )


@dataclass(frozen=True)
class DeadLetterEntry:
    entry_id: str
    original_job_id: str
    original_entry_id: str
    reason: str = ""
    payload: str = ""
    target: str = ""
    retry_count: int = 0
    failed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class QueueMetrics:
    total_queued: int = 0
    total_assigned: int = 0
    total_running: int = 0
    total_completed: int = 0
    total_failed: int = 0
    total_cancelled: int = 0
    total_retrying: int = 0
    total_expired: int = 0
    total_dead_letter: int = 0
    average_wait_seconds: float = 0.0
    oldest_job_age_seconds: float = 0.0
