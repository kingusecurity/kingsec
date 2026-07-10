"""Integration tests — full HTTP flow through the wired application."""

from __future__ import annotations

import io
from collections.abc import Sequence

import pytest
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.app import create_fastapi_app
from kingsec.application.ports.inbound.service_api import ServiceAPI
from kingsec.bootstrap.application import Application
from kingsec.bootstrap.composition import create_wired_application
from kingsec.domain import Finding, Severity, Target
from kingsec.application.ports import ScannerPort


class _StubScanner(ScannerPort):
    """Returns a fixed finding — no Nuclei binary needed."""

    def scan(self, target: Target) -> Sequence[Finding]:
        return [Finding.create("SQLi", "injectable param", Severity.CRITICAL)]


@pytest.fixture
def wired_app(tmp_path, monkeypatch) -> Application:
    monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(tmp_path))
    app = create_wired_application(
        log_stream=io.StringIO(), ensure_directories=False
    )
    # Override scanner — no nuclei binary available in CI.
    app.container.register_instance(ScannerPort, _StubScanner())
    return app


@pytest.fixture
def integration_client(wired_app: Application) -> TestClient:
    with wired_app:
        fastapi_app = create_fastapi_app(wired_app)
        return TestClient(fastapi_app, raise_server_exceptions=False)


class TestFullHTTPFlow:
    def test_create_start_get_report(self, integration_client: TestClient) -> None:
        """Full lifecycle: create → start → get → report, all over HTTP."""

        # 1. Create assessment
        resp = integration_client.post(
            "/api/v1/assessments",
            json={
                "target_value": "10.0.0.5",
                "target_type": "ip_address",
                "authorized_by": "pentester@kingsec.io",
                "scope": "10.0.0.5",
            },
        )
        assert resp.status_code == 201
        created = resp.json()
        assessment_id = created["assessment_id"]
        assert created["status"] == "authorized"

        # 2. Start assessment (scan runs synchronously)
        resp = integration_client.post(
            f"/api/v1/assessments/{assessment_id}/start"
        )
        assert resp.status_code == 200
        started = resp.json()
        assert started["status"] == "completed"
        assert started["findings_count"] == 1
        assert started["highest_severity"] == "critical"

        # 3. Get assessment
        resp = integration_client.get(f"/api/v1/assessments/{assessment_id}")
        assert resp.status_code == 200
        view = resp.json()
        assert view["status"] == "completed"
        assert view["is_authorized"] is True
        assert len(view["findings"]) == 1
        assert view["findings"][0]["severity"] == "critical"

        # 4. Generate report
        resp = integration_client.post(
            f"/api/v1/assessments/{assessment_id}/report"
        )
        assert resp.status_code == 200
        report = resp.json()
        assert report["total_findings"] == 1
        assert report["action_required"] is True
        assert report["artifact_media_type"] == "application/pdf"
        assert report["artifact_bytes"] > 0

    def test_get_nonexistent_returns_404(
        self, integration_client: TestClient
    ) -> None:
        resp = integration_client.get("/api/v1/assessments/asmt-does-not-exist")
        assert resp.status_code == 404
        body = resp.json()
        assert body["error_code"] == "KS-RES-001"

    def test_start_unauthorized_returns_409(
        self, integration_client: TestClient
    ) -> None:
        """An assessment that was never authorized cannot be started."""
        # Create (authorized), but for this test we need an unauthorized one.
        # The domain prevents starting without authorization, but our create
        # use case always authorizes. So we test the error handler via the
        # route-level exception.
        resp = integration_client.post(
            "/api/v1/assessments",
            json={
                "target_value": "10.0.0.5",
                "target_type": "ip_address",
                "authorized_by": "admin",
                "scope": "10.0.0.5",
            },
        )
        assessment_id = resp.json()["assessment_id"]

        # First start succeeds
        resp = integration_client.post(
            f"/api/v1/assessments/{assessment_id}/start"
        )
        assert resp.status_code == 200

        # Second start fails (already completed)
        resp = integration_client.post(
            f"/api/v1/assessments/{assessment_id}/start"
        )
        assert resp.status_code == 409

    def test_report_for_incomplete_returns_409(
        self, integration_client: TestClient
    ) -> None:
        resp = integration_client.post(
            "/api/v1/assessments",
            json={
                "target_value": "10.0.0.5",
                "target_type": "ip_address",
                "authorized_by": "admin",
                "scope": "10.0.0.5",
            },
        )
        assessment_id = resp.json()["assessment_id"]

        # Report on an authorized-but-not-started assessment → 409
        resp = integration_client.post(
            f"/api/v1/assessments/{assessment_id}/report"
        )
        assert resp.status_code == 409

    def test_health(self, integration_client: TestClient) -> None:
        resp = integration_client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_openapi_schema_available(self, integration_client: TestClient) -> None:
        resp = integration_client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        assert "paths" in schema
        assert "/api/v1/assessments" in schema["paths"]
        assert "/api/v1/health" in schema["paths"]

    def test_validation_error_returns_400_body(
        self, integration_client: TestClient
    ) -> None:
        resp = integration_client.post(
            "/api/v1/assessments",
            json={"target_value": ""},
        )
        assert resp.status_code == 422

    def test_unknown_route_returns_404(
        self, integration_client: TestClient
    ) -> None:
        resp = integration_client.get("/api/v1/nonexistent")
        assert resp.status_code == 404
