from __future__ import annotations

from kingsec.application.ports.outbound import (
    HealthRepositoryPort,
    LifecycleManagerPort,
    LoggingPort,
    MetricsCollectorPort,
    SystemMonitorPort,
)
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.production_service import ProductionServicePort
from kingsec.application.use_cases.production import (
    CollectMetrics,
    GetHealth,
    GetLiveness,
    GetReadiness,
    GetSystemResources,
    ListDependencies,
    RestartService,
    ShutdownGracefully,
    ValidateConfiguration,
    ValidateStartup,
)
from kingsec.domain.system_health import (
    DependencyHealth,
    HealthCheck,
    LivenessReport,
    ReadinessReport,
    StartupCheck,
    SystemMetrics,
)


class ProductionService(ProductionServicePort):
    def __init__(self, monitor: SystemMonitorPort, collector: MetricsCollectorPort,
                 repo: HealthRepositoryPort, lifecycle: LifecycleManagerPort,
                 logger: LoggingPort, audit: AuditPublisher) -> None:
        self._health_uc = GetHealth(monitor, audit)
        self._liveness_uc = GetLiveness(monitor, lifecycle, audit)
        self._readiness_uc = GetReadiness(monitor, audit)
        self._metrics_uc = CollectMetrics(collector, repo, logger)
        self._startup_uc = ValidateStartup(monitor, repo)
        self._config_uc = ValidateConfiguration(monitor)
        self._shutdown_uc = ShutdownGracefully(lifecycle, logger, audit)
        self._restart_uc = RestartService(lifecycle, logger, audit)
        self._deps_uc = ListDependencies(monitor)
        self._resources_uc = GetSystemResources(collector)

    def get_health(self) -> HealthCheck:
        return self._health_uc.execute()

    def get_liveness(self) -> LivenessReport:
        return self._liveness_uc.execute()

    def get_readiness(self) -> ReadinessReport:
        return self._readiness_uc.execute()

    def collect_metrics(self) -> SystemMetrics:
        return self._metrics_uc.execute()

    def validate_startup(self) -> list[StartupCheck]:
        return self._startup_uc.execute()

    def validate_configuration(self) -> list[StartupCheck]:
        return self._config_uc.execute()

    def shutdown(self) -> None:
        self._shutdown_uc.execute()

    def restart(self) -> None:
        self._restart_uc.execute()

    def list_dependencies(self) -> list[DependencyHealth]:
        return self._deps_uc.execute()

    def get_system_resources(self) -> SystemMetrics:
        return self._resources_uc.execute()
