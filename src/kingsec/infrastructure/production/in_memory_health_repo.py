"""In-memory implementation of ``HealthRepositoryPort``."""

from __future__ import annotations

from collections import deque

from kingsec.application.ports.outbound.health_repository import HealthRepositoryPort
from kingsec.domain.system_health import DependencyHealth, HealthCheck, StartupCheck, SystemMetrics


class InMemoryHealthRepository(HealthRepositoryPort):
    def __init__(self, max_history: int = 500) -> None:
        self._checks: deque[HealthCheck] = deque(maxlen=max_history)
        self._metrics: deque[SystemMetrics] = deque(maxlen=max_history)
        self._startup_checks: list[StartupCheck] = []
        self._dep_health: list[DependencyHealth] = []

    def record_check(self, check: HealthCheck) -> None:
        self._checks.append(check)

    def get_recent_checks(self, limit: int = 100) -> list[HealthCheck]:
        return list(self._checks)[-limit:]

    def record_metric(self, metrics: SystemMetrics) -> None:
        self._metrics.append(metrics)

    def get_latest_metrics(self) -> SystemMetrics | None:
        return self._metrics[-1] if self._metrics else None

    def record_startup_check(self, check: StartupCheck) -> None:
        self._startup_checks.append(check)

    def get_startup_checks(self) -> list[StartupCheck]:
        return list(self._startup_checks)

    def record_dependency_health(self, dep: DependencyHealth) -> None:
        self._dep_health.append(dep)

    def get_dependency_health(self) -> list[DependencyHealth]:
        return list(self._dep_health)
