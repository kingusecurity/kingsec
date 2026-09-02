"""Tests for metrics_routes.py's /metrics/system endpoint - KSEC-88-04.

The route's ``except Exception as exc: return {"status": "error", "detail":
str(exc)}`` returned any unexpected exception's message verbatim to any
authenticated admin - found during the Phase 88 repo-wide exception-
disclosure sweep. Fixed to log server-side and return a generic message,
matching the admin_operation_error() convention from Phase 87.

Auditing this except block also surfaced a separate, pre-existing bug: the
try block called ``collector.collect_resource_usage()``, a method
``MetricsCollectorPort`` never declared and no concrete implementation ever
defined - every real invocation of this endpoint raised ``AttributeError``
unconditionally. Fixed to call ``collect_all()``, the port method that
returns exactly the fields this handler already destructures.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from kingsec.application.ports.outbound.metrics_collector import MetricsCollectorPort
from kingsec.domain import Role
from kingsec.domain.system_health import ResourceUsage


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
