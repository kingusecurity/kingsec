"""Tests for metrics_routes.py's endpoints - KSEC-88-04 and KSEC-89-02/03.

/metrics/system (KSEC-88-04): the route's ``except Exception as exc: return
{"status": "error", "detail": str(exc)}`` returned any unexpected
exception's message verbatim to any authenticated admin - found during the
Phase 88 repo-wide exception-disclosure sweep. Fixed to log server-side and
return a generic message, matching the admin_operation_error() convention
from Phase 87.

Auditing that except block also surfaced a separate, pre-existing bug: the
try block called ``collector.collect_resource_usage()``, a method
``MetricsCollectorPort`` never declared and no concrete implementation ever
defined - every real invocation of this endpoint raised ``AttributeError``
unconditionally. Fixed to call ``collect_all()``, the port method that
returns exactly the fields this handler already destructures.

/metrics/performance and /metrics/operations (KSEC-89-02): Phase 89 audited
these two siblings for the same class of interface drift and found none -
both call methods (``snapshot()``/``get_operation_stats()``) that
``PerformanceMetricsPort`` declares and ``PerformanceMetrics`` (the concrete
class wired in composition.py) implements, and every attribute the route
reads exists on the returned dataclasses. Unlike /metrics/system, neither
handler wraps its call in a local ``try/except`` at all - an unexpected
failure here already propagates to the Phase 87 global exception handler
(``handle_unhandled_exception``), which already logs server-side and
returns a generic response. The tests below use the REAL ``PerformanceMetrics``
collector (not a mock) precisely to prove the declared methods genuinely
exist and work end-to-end, per KSEC-89-03's preference for exercising the
actual concrete implementation over mocking a method into existence.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application.ports.outbound.metrics_collector import MetricsCollectorPort
from kingsec.application.ports.outbound.performance_metrics import PerformanceMetricsPort
from kingsec.domain import Role
from kingsec.domain.system_health import ResourceUsage
from kingsec.infrastructure.monitoring.performance_metrics import PerformanceMetrics


@pytest.fixture
def mock_collector() -> MagicMock:
    collector = MagicMock(spec=MetricsCollectorPort)
    collector.collect_all.return_value = ResourceUsage(
        cpu_percent=12.5,
        memory_percent=40.0,
        memory_used_mb=2048.0,
        disk_percent=55.0,
        disk_used_gb=100.0,
    )
    return collector


def _make_client(collector: MagicMock | None, *, role: Role = Role.ADMIN) -> TestClient:
    with patch("kingsec.bootstrap.application.Application") as MockApp:
        app_instance = MockApp()
        if collector is None:
            app_instance.resolve.side_effect = RuntimeError("port not registered")
        else:
            app_instance.resolve.return_value = collector

        from fastapi import FastAPI

        from kingsec.adapters.inbound.web.auth import get_current_user
        from kingsec.adapters.inbound.web.metrics_routes import router

        app = FastAPI()
        app.include_router(router)
        app.state.kingsec_app = app_instance
        app.dependency_overrides[get_current_user] = lambda: type(
            "User", (), {"id": "u1", "username": "u1", "role": role, "claims": None}
        )()
        return TestClient(app)


class TestSystemMetricsAccessControl:
    def test_non_admin_is_refused(self, mock_collector: MagicMock) -> None:
        client = _make_client(mock_collector, role=Role.VIEWER)
        resp = client.get("/api/v1/metrics/system")
        assert resp.status_code == 200
        assert resp.json() == {"detail": "Admin access required"}

    def test_missing_collector_reports_unavailable(self) -> None:
        client = _make_client(None)
        resp = client.get("/api/v1/metrics/system")
        assert resp.status_code == 200
        assert resp.json()["status"] == "unavailable"


class TestSystemMetricsHappyPath:
    def test_successful_collection_returns_real_metrics(self, mock_collector: MagicMock) -> None:
        """Regression test for the collect_resource_usage() -> collect_all()
        fix: the endpoint must actually succeed against a real collector,
        not merely fail safely."""
        client = _make_client(mock_collector)
        resp = client.get("/api/v1/metrics/system")
        assert resp.status_code == 200
        body = resp.json()
        assert body["cpu_percent"] == 12.5
        assert body["memory_percent"] == 40.0
        assert body["disk_used_gb"] == 100.0


class TestSystemMetricsUnexpectedFailureDisclosure:
    def test_unexpected_exception_does_not_expose_its_message(self, mock_collector: MagicMock) -> None:
        mock_collector.collect_all.side_effect = RuntimeError(
            "Permission denied: /proc/self/status (uid=999)"
        )
        client = _make_client(mock_collector)
        resp = client.get("/api/v1/metrics/system")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "error"
        assert "/proc/self/status" not in body["detail"]
        assert "999" not in body["detail"]
        assert body["detail"] == "Failed to collect system metrics"

    def test_unexpected_exception_is_logged_server_side(self, mock_collector: MagicMock) -> None:
        mock_collector.collect_all.side_effect = RuntimeError("boom")
        client = _make_client(mock_collector)

        from kingsec.adapters.inbound.web import metrics_routes as metrics_routes_module

        class _RecordingLogger:
            def __init__(self) -> None:
                self.exception_calls: list[tuple[str, dict]] = []

            def exception(self, msg: str, **kwargs: object) -> None:
                self.exception_calls.append((msg, kwargs))

        recorder = _RecordingLogger()
        original_logger = metrics_routes_module._logger
        metrics_routes_module._logger = recorder
        try:
            client.get("/api/v1/metrics/system")
        finally:
            metrics_routes_module._logger = original_logger

        assert len(recorder.exception_calls) == 1
        assert recorder.exception_calls[0][0] == "failed to collect system resource metrics"


def _make_perf_client(
    metrics: PerformanceMetrics | None, *, role: Role = Role.ADMIN, with_error_handlers: bool = False
) -> TestClient:
    """Same shape as ``_make_client`` above, but resolves
    ``PerformanceMetricsPort`` instead of ``MetricsCollectorPort`` - the two
    metrics ports are resolved by different routes in the same router and
    a single ``resolve.return_value`` can only stand in for one of them."""
    with patch("kingsec.bootstrap.application.Application") as MockApp:
        app_instance = MockApp()
        if metrics is None:
            app_instance.resolve.side_effect = RuntimeError("port not registered")
        else:
            app_instance.resolve.return_value = metrics

        from kingsec.adapters.inbound.web.auth import get_current_user
        from kingsec.adapters.inbound.web.metrics_routes import router

        app = FastAPI()
        app.include_router(router)
        if with_error_handlers:
            from kingsec.adapters.inbound.web.error_handlers import register_error_handlers

            register_error_handlers(app)
        app.state.kingsec_app = app_instance
        app.dependency_overrides[get_current_user] = lambda: type(
            "User", (), {"id": "u1", "username": "u1", "role": role, "claims": None}
        )()
        return TestClient(app, raise_server_exceptions=not with_error_handlers)


class TestPerformanceMetricsEndpoint:
    """KSEC-89-03: real PerformanceMetrics() collector, not a mock - proves
    snapshot() genuinely exists and works, not merely that a mock permits
    the call."""

    def test_non_admin_is_refused(self) -> None:
        client = _make_perf_client(PerformanceMetrics(), role=Role.VIEWER)
        resp = client.get("/api/v1/metrics/performance")
        assert resp.status_code == 200
        assert resp.json() == {"detail": "Admin access required"}

    def test_missing_metrics_reports_unavailable(self) -> None:
        client = _make_perf_client(None)
        resp = client.get("/api/v1/metrics/performance")
        assert resp.status_code == 200
        assert resp.json()["status"] == "unavailable"

    def test_authorized_access_returns_the_expected_structure(self) -> None:
        metrics = PerformanceMetrics()
        metrics.record_request(latency_ms=42.0)
        metrics.record_cache_hit()
        metrics.increment_assessment()

        client = _make_perf_client(metrics)
        resp = client.get("/api/v1/metrics/performance")
        assert resp.status_code == 200
        body = resp.json()
        assert "timestamp" in body
        assert body["request_latency"]["count"] == 1
        assert body["request_latency"]["avg_ms"] == 42.0
        assert body["cache"]["hits"] == 1
        assert body["system"]["assessment_count"] == 1
        assert set(body["throughput"]) == {"requests_per_second", "total_requests", "error_count", "error_rate"}

    def test_unexpected_failure_does_not_disclose_raw_exception_text(self) -> None:
        """No local except block exists in this handler (see module
        docstring) - an unexpected failure must still reach the client
        safely, via the Phase 87 global handler rather than a local one."""
        broken = MagicMock(spec=PerformanceMetricsPort)
        broken.snapshot.side_effect = RuntimeError("dsn=postgresql://admin:hunter2@10.0.0.5/kingsec")

        client = _make_perf_client(broken, with_error_handlers=True)
        resp = client.get("/api/v1/metrics/performance")
        assert resp.status_code == 500
        assert "hunter2" not in resp.text
        assert "10.0.0.5" not in resp.text
        assert "postgresql" not in resp.text


class TestMetricsAuthenticationRequired:
    """KSEC-89-04: every previous test in this file overrides
    ``get_current_user`` entirely (a fixed test user), which proves
    role-based rejection but not that a genuinely unauthenticated request
    (no credential at all) is rejected. This exercises the REAL,
    un-overridden dependency chain to prove that directly - confirming no
    endpoint accidentally became reachable without authentication while
    fixing the interface-drift/disclosure issues in this file."""

    def _make_unauthenticated_client(self) -> TestClient:
        with patch("kingsec.bootstrap.application.Application") as MockApp:
            app_instance = MockApp()

            from kingsec.adapters.inbound.web.metrics_routes import router

            app = FastAPI()
            app.include_router(router)
            app.state.kingsec_app = app_instance
            # No dependency_overrides at all - get_current_user runs for real.
            return TestClient(app)

    def test_system_metrics_rejects_a_request_with_no_credentials(self) -> None:
        client = self._make_unauthenticated_client()
        resp = client.get("/api/v1/metrics/system")
        assert resp.status_code == 401

    def test_performance_metrics_rejects_a_request_with_no_credentials(self) -> None:
        client = self._make_unauthenticated_client()
        resp = client.get("/api/v1/metrics/performance")
        assert resp.status_code == 401

    def test_operation_metrics_rejects_a_request_with_no_credentials(self) -> None:
        client = self._make_unauthenticated_client()
        resp = client.get("/api/v1/metrics/operations")
        assert resp.status_code == 401


class TestOperationMetricsEndpoint:
    """Same standard as TestPerformanceMetricsEndpoint, for
    /metrics/operations and get_operation_stats()."""

    def test_non_admin_is_refused(self) -> None:
        client = _make_perf_client(PerformanceMetrics(), role=Role.VIEWER)
        resp = client.get("/api/v1/metrics/operations")
        assert resp.status_code == 200
        assert resp.json() == {"detail": "Admin access required"}

    def test_missing_metrics_reports_unavailable(self) -> None:
        client = _make_perf_client(None)
        resp = client.get("/api/v1/metrics/operations")
        assert resp.status_code == 200
        assert resp.json()["status"] == "unavailable"

    def test_authorized_access_returns_the_expected_structure(self) -> None:
        metrics = PerformanceMetrics()
        metrics.record_operation("assessment", duration_ms=100.0)
        metrics.record_operation("assessment", duration_ms=200.0)

        client = _make_perf_client(metrics)
        resp = client.get("/api/v1/metrics/operations")
        assert resp.status_code == 200
        body = resp.json()
        assert body["operations"]["assessment"]["count"] == 2
        assert body["operations"]["assessment"]["avg_ms"] == 150.0
        # An operation with zero recorded samples must not appear at all
        # (the route's own `if stats.count > 0` filter) - not as a
        # zero-valued entry.
        assert "report" not in body["operations"]

    def test_unexpected_failure_does_not_disclose_raw_exception_text(self) -> None:
        broken = MagicMock(spec=PerformanceMetricsPort)
        broken.get_operation_stats.side_effect = RuntimeError("dsn=postgresql://admin:hunter2@10.0.0.5/kingsec")

        client = _make_perf_client(broken, with_error_handlers=True)
        resp = client.get("/api/v1/metrics/operations")
        assert resp.status_code == 500
        assert "hunter2" not in resp.text
        assert "10.0.0.5" not in resp.text
        assert "postgresql" not in resp.text
