from __future__ import annotations

from kingsec.application.ports.outbound import (
    HealthRepositoryPort,
    LifecycleManagerPort,
    LoggingPort,
    MetricsCollectorPort,
    SystemMonitorPort,
)
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.system_health import (
    DependencyHealth,
    HealthCheck,
    HealthStatus,
    LivenessReport,
    ReadinessReport,
    StartupCheck,
    SystemMetrics,
)


class GetHealth:
    def __init__(self, monitor: SystemMonitorPort, audit: AuditPublisher) -> None:
        self._monitor = monitor
        self._audit = audit

    def execute(self) -> HealthCheck:
        checks = self._monitor.check_all()
        worst = HealthStatus.HEALTHY
        for c in checks:
            if c.status.value == "unhealthy":
                worst = HealthStatus.UNHEALTHY
            elif c.status.value == "degraded" and worst.value == "healthy":
                worst = HealthStatus.DEGRADED
        overall = HealthCheck(name="overall", status=worst)
        self._audit.record(AuditEntry(
            action=AuditAction.HEALTH_CHECK,
            resource_type="system",
            success=worst != HealthStatus.UNHEALTHY,
        ))
        return overall


class GetLiveness:
    def __init__(self, monitor: SystemMonitorPort, lifecycle: LifecycleManagerPort,
                 audit: AuditPublisher) -> None:
        self._monitor = monitor
        self._lifecycle = lifecycle
        self._audit = audit

    def execute(self) -> LivenessReport:
        alive = self._lifecycle.is_running()
        report = self._monitor.get_liveness()
        self._audit.record(AuditEntry(
            action=AuditAction.LIVENESS_CHECK,
            resource_type="system",
            success=alive,
        ))
        return report


class GetReadiness:
    def __init__(self, monitor: SystemMonitorPort, audit: AuditPublisher) -> None:
        self._monitor = monitor
        self._audit = audit

    def execute(self) -> ReadinessReport:
        report = self._monitor.get_readiness()
        self._audit.record(AuditEntry(
            action=AuditAction.READINESS_CHECK,
            resource_type="system",
            success=report.ready,
        ))
        return report


class CollectMetrics:
    def __init__(self, collector: MetricsCollectorPort, repo: HealthRepositoryPort,
                 logger: LoggingPort) -> None:
        self._collector = collector
        self._repo = repo
        self._logger = logger

    def execute(self) -> SystemMetrics:
        try:
            usage = self._collector.collect_all()
            metrics = SystemMetrics(
                cpu_percent=usage.cpu_percent,
                memory_percent=usage.memory_percent,
                memory_used_mb=usage.memory_used_mb,
                disk_percent=usage.disk_percent,
                disk_used_gb=usage.disk_used_gb,
            )
            self._repo.record_metric(metrics)
            return metrics
        except Exception as exc:
            self._logger.error("Failed to collect metrics", error=str(exc))
            return SystemMetrics()


class ValidateStartup:
    def __init__(self, monitor: SystemMonitorPort, repo: HealthRepositoryPort) -> None:
        self._monitor = monitor
        self._repo = repo

    def execute(self) -> list[StartupCheck]:
        checks = self._monitor.validate_startup()
        for c in checks:
            self._repo.record_startup_check(c)
        return checks


class ValidateConfiguration:
    def __init__(self, monitor: SystemMonitorPort) -> None:
        self._monitor = monitor

    def execute(self) -> list[StartupCheck]:
        check = self._monitor.check_configuration()
        return [
            StartupCheck(
                name="configuration",
                passed=check.status != HealthStatus.UNHEALTHY,
                message=check.message,
            ),
        ]


class ShutdownGracefully:
    def __init__(self, lifecycle: LifecycleManagerPort, logger: LoggingPort,
                 audit: AuditPublisher) -> None:
        self._lifecycle = lifecycle
        self._logger = logger
        self._audit = audit

    def execute(self) -> None:
        self._logger.info("System shutdown initiated")
        self._audit.record(AuditEntry(
            action=AuditAction.SYSTEM_STOPPED,
            resource_type="system",
            success=True,
        ))
        self._lifecycle.shutdown()


class RestartService:
    def __init__(self, lifecycle: LifecycleManagerPort, logger: LoggingPort,
                 audit: AuditPublisher) -> None:
        self._lifecycle = lifecycle
        self._logger = logger
        self._audit = audit

    def execute(self) -> None:
        self._logger.info("System restart initiated")
        self._audit.record(AuditEntry(
            action=AuditAction.SYSTEM_RESTARTED,
            resource_type="system",
            success=True,
        ))
        self._lifecycle.restart()


class ListDependencies:
    def __init__(self, monitor: SystemMonitorPort) -> None:
        self._monitor = monitor

    def execute(self) -> list[DependencyHealth]:
        return self._monitor.get_dependencies()


class GetSystemResources:
    def __init__(self, collector: MetricsCollectorPort) -> None:
        self._collector = collector

    def execute(self) -> SystemMetrics:
        usage = self._collector.collect_all()
        return SystemMetrics(
            cpu_percent=usage.cpu_percent,
            memory_percent=usage.memory_percent,
            memory_used_mb=usage.memory_used_mb,
            disk_percent=usage.disk_percent,
            disk_used_gb=usage.disk_used_gb,
        )
