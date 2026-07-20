from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass(frozen=True)
class HealthCheck:
    name: str
    status: HealthStatus
    message: str = ""
    latency_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class DependencyHealth:
    name: str
    status: HealthStatus
    latency_ms: float = 0.0
    last_checked: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    error_message: str = ""


@dataclass(frozen=True)
class SystemMetrics:
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_used_mb: float = 0.0
    disk_percent: float = 0.0
    disk_used_gb: float = 0.0
    open_jobs: int = 0
    worker_count: int = 0
    agent_count: int = 0
    queue_depth: int = 0
    notification_backlog: int = 0
    pipeline_count: int = 0
    schedule_count: int = 0
    uptime_seconds: float = 0.0
    collected_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class ResourceUsage:
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_used_mb: float = 0.0
    disk_percent: float = 0.0
    disk_used_gb: float = 0.0


@dataclass(frozen=True)
class ServiceStatus:
    service_name: str
    status: str
    uptime_seconds: float = 0.0
    version: str = ""
    started_at: str = ""


@dataclass(frozen=True)
class StartupCheck:
    name: str
    passed: bool
    message: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class ReadinessReport:
    ready: bool
    overall_status: HealthStatus
    checks: tuple[HealthCheck, ...] = ()
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class LivenessReport:
    alive: bool
    status: HealthStatus
    uptime_seconds: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
