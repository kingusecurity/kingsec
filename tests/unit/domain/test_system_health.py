from __future__ import annotations

import pytest
from kingsec.domain.system_health import (
    DependencyHealth,
    HealthCheck,
    HealthStatus,
    LivenessReport,
    ReadinessReport,
    ResourceUsage,
    ServiceStatus,
    StartupCheck,
    SystemMetrics,
)


class TestHealthStatus:
    def test_values(self) -> None:
        assert HealthStatus.HEALTHY == "healthy"
        assert HealthStatus.DEGRADED == "degraded"
        assert HealthStatus.UNHEALTHY == "unhealthy"


class TestHealthCheck:
    def test_default_message(self) -> None:
        c = HealthCheck(name="db", status=HealthStatus.HEALTHY)
        assert c.name == "db"
        assert c.status == HealthStatus.HEALTHY
        assert c.message == ""
        assert c.latency_ms == 0.0
        assert c.timestamp != ""

    def test_frozen(self) -> None:
        c = HealthCheck(name="db", status=HealthStatus.HEALTHY)
        with pytest.raises(AttributeError):
            c.name = "cache"  # type: ignore[misc]


class TestDependencyHealth:
    def test_defaults(self) -> None:
        d = DependencyHealth(name="database", status=HealthStatus.HEALTHY)
        assert d.latency_ms == 0.0
        assert d.error_message == ""
        assert d.last_checked != ""


class TestSystemMetrics:
    def test_defaults(self) -> None:
        m = SystemMetrics()
        assert m.cpu_percent == 0.0
        assert m.memory_percent == 0.0
        assert m.open_jobs == 0
        assert m.collected_at != ""


class TestResourceUsage:
    def test_fields(self) -> None:
        r = ResourceUsage(cpu_percent=45.0, memory_percent=60.0, memory_used_mb=1024.0, disk_percent=50.0, disk_used_gb=100.0)
        assert r.cpu_percent == 45.0
        assert r.memory_percent == 60.0


class TestServiceStatus:
    def test_fields(self) -> None:
        s = ServiceStatus(service_name="kingsec", status="running")
        assert s.service_name == "kingsec"
        assert s.status == "running"
        assert s.uptime_seconds == 0.0


class TestStartupCheck:
    def test_defaults(self) -> None:
        s = StartupCheck(name="config", passed=True)
        assert s.passed is True
        assert s.message == ""


class TestReadinessReport:
    def test_ready(self) -> None:
        r = ReadinessReport(ready=True, overall_status=HealthStatus.HEALTHY)
        assert r.ready is True
        assert r.overall_status == HealthStatus.HEALTHY
        assert r.checks == ()


class TestLivenessReport:
    def test_alive(self) -> None:
        r = LivenessReport(alive=True, status=HealthStatus.HEALTHY)
        assert r.alive is True
        assert r.uptime_seconds == 0.0
