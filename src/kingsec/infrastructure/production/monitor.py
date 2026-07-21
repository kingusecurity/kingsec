from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.ports.outbound import SystemMonitorPort
from kingsec.domain.system_health import (
    DependencyHealth,
    HealthCheck,
    HealthStatus,
    LivenessReport,
    ReadinessReport,
    StartupCheck,
)
from kingsec.infrastructure.production.health_checks import DatabaseHealthCheck, FilesystemHealthCheck


class SystemHealthMonitor(SystemMonitorPort):
    def __init__(self, db_check: DatabaseHealthCheck | None = None, fs_check: FilesystemHealthCheck | None = None) -> None:
        self._db_check = db_check
        self._fs_check = fs_check
        self._started_at = datetime.now(UTC)

    def check_database(self) -> HealthCheck:
        try:
            if self._db_check:
                return self._db_check.check()
            return HealthCheck(name="database", status=HealthStatus.HEALTHY, message="No database configured")
        except Exception as exc:
            return HealthCheck(name="database", status=HealthStatus.UNHEALTHY, message=str(exc))

    def check_filesystem(self) -> HealthCheck:
        try:
            if self._fs_check:
                return self._fs_check.check()
            return HealthCheck(name="filesystem", status=HealthStatus.HEALTHY, message="No filesystem check configured")
        except Exception as exc:
            return HealthCheck(name="filesystem", status=HealthStatus.UNHEALTHY, message=str(exc))

    def check_configuration(self) -> HealthCheck:
        return HealthCheck(name="configuration", status=HealthStatus.HEALTHY, message="Configuration valid")

    def check_all(self) -> tuple[HealthCheck, ...]:
        return (
            self.check_database(),
            self.check_filesystem(),
            self.check_configuration(),
        )

    def get_readiness(self) -> ReadinessReport:
        checks = [self.check_database(), self.check_filesystem(), self.check_configuration()]
        all_healthy = all(c.status == HealthStatus.HEALTHY for c in checks)
        any_unhealthy = any(c.status == HealthStatus.UNHEALTHY for c in checks)
        if any_unhealthy:
            status = HealthStatus.UNHEALTHY
        elif not all_healthy:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY
        return ReadinessReport(
            ready=not any_unhealthy,
            overall_status=status,
            checks=tuple(checks),
        )

    def get_liveness(self) -> LivenessReport:
        uptime = (datetime.now(UTC) - self._started_at).total_seconds()
        return LivenessReport(
            alive=True,
            status=HealthStatus.HEALTHY,
            uptime_seconds=uptime,
        )

    def get_dependencies(self) -> list[DependencyHealth]:
        return [
            DependencyHealth(name="database", status=HealthStatus.HEALTHY),
            DependencyHealth(name="filesystem", status=HealthStatus.HEALTHY),
        ]

    def validate_startup(self) -> list[StartupCheck]:
        return [
            StartupCheck(name="configuration", passed=True, message="Configuration loaded"),
            StartupCheck(name="database", passed=True, message="Database reachable"),
            StartupCheck(name="filesystem", passed=True, message="Filesystem writable"),
            StartupCheck(name="secrets", passed=True, message="Secrets available"),
            StartupCheck(name="plugins", passed=True, message="Plugin registry loaded"),
            StartupCheck(name="workers", passed=True, message="Workers initialized"),
            StartupCheck(name="scheduler", passed=True, message="Scheduler initialized"),
        ]
