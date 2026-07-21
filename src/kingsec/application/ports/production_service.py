from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.system_health import (
    DependencyHealth,
    HealthCheck,
    LivenessReport,
    ReadinessReport,
    StartupCheck,
    SystemMetrics,
)
from kingsec.domain.system_health import (
    SystemMetrics as SystemResources,
)


class ProductionServicePort(ABC):
    @abstractmethod
    def get_health(self) -> HealthCheck:
        ...

    @abstractmethod
    def get_liveness(self) -> LivenessReport:
        ...

    @abstractmethod
    def get_readiness(self) -> ReadinessReport:
        ...

    @abstractmethod
    def collect_metrics(self) -> SystemMetrics:
        ...

    @abstractmethod
    def validate_startup(self) -> list[StartupCheck]:
        ...

    @abstractmethod
    def validate_configuration(self) -> list[StartupCheck]:
        ...

    @abstractmethod
    def shutdown(self) -> None:
        ...

    @abstractmethod
    def restart(self) -> None:
        ...

    @abstractmethod
    def list_dependencies(self) -> list[DependencyHealth]:
        ...

    @abstractmethod
    def get_system_resources(self) -> SystemResources:
        ...
