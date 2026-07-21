"""Enterprise distributed scan agent domain — pure domain, no framework dependencies."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class AgentPlatform(StrEnum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class AgentArchitecture(StrEnum):
    AMD64 = "amd64"
    ARM64 = "arm64"


class AgentState(StrEnum):
    OFFLINE = "offline"
    ONLINE = "online"
    BUSY = "busy"
    MAINTENANCE = "maintenance"
    DISABLED = "disabled"


@dataclass(frozen=True)
class AgentId:
    value: str

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class AgentCapability:
    max_concurrent_jobs: int = 1
    supported_scanners: tuple[str, ...] = ()
    max_memory_mb: int = 1024
    max_disk_mb: int = 10240


@dataclass(frozen=True)
class AgentHealth:
    cpu_usage_percent: float = 0.0
    memory_usage_percent: float = 0.0
    disk_usage_percent: float = 0.0
    uptime_seconds: int = 0
    error_message: str = ""


@dataclass(frozen=True)
class AgentRegistration:
    agent_id: AgentId
    name: str
    platform: AgentPlatform
    architecture: AgentArchitecture
    version: str
    hostname: str
    capability: AgentCapability
    api_key_hash: str
    registered_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class AgentHeartbeat:
    agent_id: AgentId
    state: AgentState
    health: AgentHealth
    current_job_id: str | None = None
    jobs_completed: int = 0
    jobs_failed: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class AgentStatistics:
    total_jobs_assigned: int = 0
    total_jobs_completed: int = 0
    total_jobs_failed: int = 0
    uptime_seconds: int = 0
    last_heartbeat_at: str = ""


@dataclass(frozen=True)
class Agent:
    id: AgentId
    name: str
    platform: AgentPlatform
    architecture: AgentArchitecture
    version: str
    hostname: str
    state: AgentState
    capability: AgentCapability
    api_key_hash: str
    health: AgentHealth = field(default_factory=AgentHealth)
    statistics: AgentStatistics = field(default_factory=AgentStatistics)
    current_job_id: str | None = None
    registered_at: str = ""
    last_heartbeat_at: str = ""
    tags: tuple[str, ...] = ()
