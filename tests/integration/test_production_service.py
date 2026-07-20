from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kingsec.application.ports.outbound import (
    HealthRepositoryPort,
    LifecycleManagerPort,
    LoggingPort,
    MetricsCollectorPort,
    SystemMonitorPort,
)
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.production_service import ProductionServicePort
from kingsec.application.production_service import ProductionService
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.system_health import (
    DependencyHealth,
    HealthCheck,
    HealthStatus,
    LivenessReport,
    ReadinessReport,
    ResourceUsage,
    StartupCheck,
    SystemMetrics,
)


class InMemoryHealthRepo(HealthRepositoryPort):
    def __init__(self) -> None:
        self.checks: list[HealthCheck] = []
        self.metrics: list[SystemMetrics] = []
        self.startup_checks: list[StartupCheck] = []
        self.deps: list[DependencyHealth] = []

    def record_check(self, check: HealthCheck) -> None:
        self.checks.append(check)

    def get_recent_checks(self, limit: int = 100) -> list[HealthCheck]:
        return self.checks[-limit:]

    def record_metric(self, metrics: SystemMetrics) -> None:
        self.metrics.append(metrics)

    def get_latest_metrics(self) -> SystemMetrics | None:
        return self.metrics[-1] if self.metrics else None

    def record_startup_check(self, check: StartupCheck) -> None:
        self.startup_checks.append(check)

    def get_startup_checks(self) -> list[StartupCheck]:
        return self.startup_checks

    def record_dependency_health(self, dep: DependencyHealth) -> None:
        self.deps.append(dep)

    def get_dependency_health(self) -> list[DependencyHealth]:
        return self.deps


class FakeMonitor(SystemMonitorPort):
    def __init__(self) -> None:
        self._started = datetime.now(UTC)

    def check_database(self) -> HealthCheck:
        return HealthCheck(name="database", status=HealthStatus.HEALTHY, message="ok")

    def check_filesystem(self) -> HealthCheck:
        return HealthCheck(name="filesystem", status=HealthStatus.HEALTHY, message="ok")

    def check_configuration(self) -> HealthCheck:
        return HealthCheck(name="configuration", status=HealthStatus.HEALTHY, message="valid")

    def check_all(self) -> tuple[HealthCheck, ...]:
        return (self.check_database(), self.check_filesystem(), self.check_configuration())

    def get_readiness(self) -> ReadinessReport:
        return ReadinessReport(ready=True, overall_status=HealthStatus.HEALTHY)

    def get_liveness(self) -> LivenessReport:
        uptime = (datetime.now(UTC) - self._started).total_seconds()
        return LivenessReport(alive=True, status=HealthStatus.HEALTHY, uptime_seconds=uptime)

    def get_dependencies(self) -> list[DependencyHealth]:
        return [DependencyHealth(name="db", status=HealthStatus.HEALTHY)]

    def validate_startup(self) -> list[StartupCheck]:
        return [StartupCheck(name="db", passed=True)]


class FakeCollector(MetricsCollectorPort):
    def collect_cpu(self) -> float:
        return 10.0

    def collect_memory(self) -> tuple[float, float]:
        return 40.0, 512.0

    def collect_disk(self) -> tuple[float, float]:
        return 50.0, 200.0

    def collect_all(self) -> ResourceUsage:
        return ResourceUsage(cpu_percent=10.0, memory_percent=40.0, memory_used_mb=512.0, disk_percent=50.0, disk_used_gb=200.0)


class FakeLifecycle(LifecycleManagerPort):
    def __init__(self) -> None:
        self._running = True

    def shutdown(self) -> None:
        self._running = False

    def restart(self) -> None:
        pass

    def is_running(self) -> bool:
        return self._running

    def uptime_seconds(self) -> float:
        return 100.0

    def get_service_status(self) -> str:
        return "running" if self._running else "stopped"


class FakeLogger(LoggingPort):
    def __init__(self) -> None:
        self.messages: list[str] = []

    def info(self, message: str, **context) -> None:
        self.messages.append(f"INFO: {message}")

    def warn(self, message: str, **context) -> None:
        self.messages.append(f"WARN: {message}")

    def error(self, message: str, **context) -> None:
        self.messages.append(f"ERROR: {message}")

    def debug(self, message: str, **context) -> None:
        self.messages.append(f"DEBUG: {message}")


class FakeAuditPublisher(AuditPublisher):
    def __init__(self) -> None:
        self.records: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        self.records.append(entry)


@pytest.fixture
def service() -> ProductionServicePort:
    return ProductionService(
        monitor=FakeMonitor(),
        collector=FakeCollector(),
        repo=InMemoryHealthRepo(),
        lifecycle=FakeLifecycle(),
        logger=FakeLogger(),
        audit=FakeAuditPublisher(),
    )


class TestProductionService:
    def test_get_health(self, service: ProductionServicePort) -> None:
        result = service.get_health()
        assert result.name == "overall"
        assert result.status == HealthStatus.HEALTHY

    def test_get_liveness(self, service: ProductionServicePort) -> None:
        result = service.get_liveness()
        assert result.alive is True
        assert result.status == HealthStatus.HEALTHY

    def test_get_readiness(self, service: ProductionServicePort) -> None:
        result = service.get_readiness()
        assert result.ready is True
        assert result.overall_status == HealthStatus.HEALTHY

    def test_collect_metrics(self, service: ProductionServicePort) -> None:
        result = service.collect_metrics()
        assert result.cpu_percent == 10.0
        assert result.memory_percent == 40.0
        assert result.disk_percent == 50.0

    def test_validate_startup(self, service: ProductionServicePort) -> None:
        result = service.validate_startup()
        assert len(result) == 1
        assert result[0].passed is True

    def test_validate_configuration(self, service: ProductionServicePort) -> None:
        result = service.validate_configuration()
        assert len(result) == 1

    def test_list_dependencies(self, service: ProductionServicePort) -> None:
        result = service.list_dependencies()
        assert len(result) == 1
        assert result[0].name == "db"

    def test_get_system_resources(self, service: ProductionServicePort) -> None:
        result = service.get_system_resources()
        assert result.cpu_percent == 10.0
        assert result.memory_percent == 40.0

    def test_shutdown(self, service: ProductionServicePort) -> None:
        service.shutdown()
        liveness = service.get_liveness()
        assert liveness.alive is True  # FakeLifecycle already stopped

    def test_restart(self, service: ProductionServicePort) -> None:
        service.restart()
        liveness = service.get_liveness()
        assert liveness.alive is True
