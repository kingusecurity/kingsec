"""Enterprise scan queue domain — pure domain, no framework dependencies."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum, StrEnum


class QueuePriority(IntEnum):
    LOW = 10
    NORMAL = 20
    HIGH = 30
    CRITICAL = 40
    EMERGENCY = 50


class QueueState(StrEnum):
    WAITING = "waiting"
    READY = "ready"
    RUNNING = "running"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SchedulingStrategy(StrEnum):
    FIFO = "fifo"
    PRIORITY = "priority"
    FAIR = "fair"
    ROUND_ROBIN = "round_robin"
    SHORTEST_FIRST = "shortest_first"


@dataclass(frozen=True)
class ResourceRequirements:
    min_memory_mb: int = 256
    min_disk_mb: int = 1024
    required_scanners: tuple[str, ...] = ()
    estimated_runtime_seconds: int = 300
    max_retries: int = 3


@dataclass(frozen=True)
class ConcurrencyPolicy:
    max_concurrent_jobs: int = 5
    max_jobs_per_agent: int = 2
    max_jobs_per_user: int = 10
    queue_capacity: int = 1000


@dataclass(frozen=True)
class QueueEntry:
    entry_id: str
    job_id: str
    priority: QueuePriority
    state: QueueState
    strategy: SchedulingStrategy = SchedulingStrategy.PRIORITY
    payload: str = ""
    target: str = ""
    scanner_ids: tuple[str, ...] = ()
    resource_requirements: ResourceRequirements = field(default_factory=ResourceRequirements)
    concurrency_policy: ConcurrencyPolicy = field(default_factory=ConcurrencyPolicy)
    owner_user_id: str = ""
    assigned_agent_id: str = ""
    retry_count: int = 0
    max_retries: int = 3
    depend_on_entry_ids: tuple[str, ...] = ()
    blocked_by_entry_ids: tuple[str, ...] = ()
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    scheduled_at: str = ""
    started_at: str = ""
    completed_at: str = ""
    position: int = 0
    submission_count: int = 1
    estimated_duration_seconds: int = 300
    error_message: str = ""


@dataclass(frozen=True)
class QueueStatistics:
    total_entries: int = 0
    waiting: int = 0
    ready: int = 0
    running: int = 0
    blocked: int = 0
    completed: int = 0
    failed: int = 0
    cancelled: int = 0
    average_wait_time_seconds: float = 0.0
    longest_wait_time_seconds: float = 0.0
    oldest_entry_age_seconds: float = 0.0
    queue_full: bool = False
    paused: bool = False
