from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.system_health import DependencyHealth, HealthCheck, StartupCheck, SystemMetrics


class HealthRepositoryPort(ABC):
    @abstractmethod
    def record_check(self, check: HealthCheck) -> None: ...

    @abstractmethod
    def get_recent_checks(self, limit: int = 100) -> list[HealthCheck]: ...

    @abstractmethod
    def record_metric(self, metrics: SystemMetrics) -> None: ...

    @abstractmethod
    def get_latest_metrics(self) -> SystemMetrics | None: ...

    @abstractmethod
    def record_startup_check(self, check: StartupCheck) -> None: ...

    @abstractmethod
    def get_startup_checks(self) -> list[StartupCheck]: ...

    @abstractmethod
    def record_dependency_health(self, dep: DependencyHealth) -> None: ...

    @abstractmethod
    def get_dependency_health(self) -> list[DependencyHealth]: ...
