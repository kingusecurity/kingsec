from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.system_health import (
    DependencyHealth,
    HealthCheck,
    LivenessReport,
    ReadinessReport,
    StartupCheck,
)


class SystemMonitorPort(ABC):
    @abstractmethod
    def check_database(self) -> HealthCheck:
        ...

    @abstractmethod
    def check_filesystem(self) -> HealthCheck:
        ...

    @abstractmethod
    def check_configuration(self) -> HealthCheck:
        ...

    @abstractmethod
    def check_all(self) -> tuple[HealthCheck, ...]:
        ...

    @abstractmethod
    def get_readiness(self) -> ReadinessReport:
        ...

    @abstractmethod
    def get_liveness(self) -> LivenessReport:
        ...

    @abstractmethod
    def get_dependencies(self) -> list[DependencyHealth]:
        ...

    @abstractmethod
    def validate_startup(self) -> list[StartupCheck]:
        ...
