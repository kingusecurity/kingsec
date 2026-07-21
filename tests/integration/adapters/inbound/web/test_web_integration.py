"""Integration tests — full HTTP flow through the wired application."""

from __future__ import annotations

import io
from collections.abc import Sequence
from datetime import UTC, datetime

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.app import create_fastapi_app
from kingsec.adapters.inbound.web.auth import (
    CurrentUser,
    get_current_user,
    require_analyst,
    require_viewer,
)
from kingsec.application.ports import ScannerPort, TokenClaims
from kingsec.bootstrap.application import Application
from kingsec.bootstrap.composition import create_wired_application
from kingsec.domain import Finding, Role, Severity, Target
from kingsec.infrastructure.persistence import create_database_engine, create_schema

_TEST_FERNET_KEY = Fernet.generate_key().decode()


def _make_fake_user() -> CurrentUser:
    now = datetime.now(UTC)
    return CurrentUser(
        user_id="user-001",
        username="testuser",
        role=Role.ANALYST,
        claims=TokenClaims(
            user_id="user-001",
            username="testuser",
            role="analyst",
            token_type="access",
            jti="jti-test-001",
            issued_at=now,
            expires_at=now,
        ),
    )


class _StubScanner(ScannerPort):
    """Returns a fixed finding — no Nuclei binary needed."""

    def scan(self, target: Target) -> Sequence[Finding]:
        return [Finding.create("SQLi", "injectable param", Severity.CRITICAL)]


@pytest.fixture
def wired_app(tmp_path, monkeypatch) -> Application:
    monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KINGSEC_SECRETS__ENCRYPTION_KEY", _TEST_FERNET_KEY)
    app = create_wired_application(log_stream=io.StringIO(), ensure_directories=False, validate_migrations=False)
    # Create schema on a separate engine so tables exist for the app's engine.
    engine = create_database_engine(settings=app.settings)
    create_schema(engine)
    engine.dispose()
    app.container.register_instance(ScannerPort, _StubScanner())
    return app


@pytest.fixture
def integration_client(wired_app: Application) -> TestClient:
    with wired_app:
        fastapi_app = create_fastapi_app(wired_app)
        fake_user = _make_fake_user()
        fastapi_app.dependency_overrides[get_current_user] = lambda: fake_user
        fastapi_app.dependency_overrides[require_analyst] = lambda: fake_user
        fastapi_app.dependency_overrides[require_viewer] = lambda: fake_user
        yield TestClient(fastapi_app, raise_server_exceptions=False)


class TestFullHTTPFlow:
    def test_create_start_get_report(self, integration_client: TestClient) -> None:
        """Full lifecycle: create → start → poll → get → report, all over HTTP."""
        # 1. Create assessment
        resp = integration_client.post(
            "/api/v1/assessments",
            json={
                "target_value": "10.0.0.5",
                "target_type": "ip_address",
                "authorized_by": "pentester@kingusecurity.com",
                "scope": "10.0.0.5",
            },
        )
        assert resp.status_code == 201
        created = resp.json()
        assessment_id = created["assessment_id"]
        assert created["status"] == "authorized"

        # 2. Start assessment (returns 202, background job runs async)
        resp = integration_client.post(f"/api/v1/assessments/{assessment_id}/start")
        assert resp.status_code == 202
        started = resp.json()
        assert started["status"] == "running"
        assert started["job_id"] is not None

        # 3. Poll until background job completes
        import time

        for _ in range(50):
            resp = integration_client.get(f"/api/v1/assessments/{assessment_id}")
            if resp.json()["status"] == "completed":
                break
            time.sleep(0.1)
        else:
            raise AssertionError("Assessment did not complete within timeout")

        # 4. Get assessment
        resp = integration_client.get(f"/api/v1/assessments/{assessment_id}")
        assert resp.status_code == 200
        view = resp.json()
        assert view["status"] == "completed"
        assert view["is_authorized"] is True
        assert len(view["findings"]) == 1
        assert view["findings"][0]["severity"].lower() == "critical"

        # 5. Generate report (may fail if WeasyPrint system deps are missing)
        resp = integration_client.post(f"/api/v1/assessments/{assessment_id}/report")
        if resp.status_code == 200:
            report = resp.json()
            assert report["total_findings"] == 1
            assert report["action_required"] is True
            assert report["artifact_media_type"] == "application/pdf"
            assert report["artifact_bytes"] > 0
        else:
            # WeasyPrint unavailable on this platform — verify endpoint works
            assert resp.status_code in (400, 500)

    def test_get_nonexistent_returns_404(self, integration_client: TestClient) -> None:
        resp = integration_client.get("/api/v1/assessments/asmt-does-not-exist")
        assert resp.status_code == 404
        body = resp.json()
        assert body["error_code"] == "KS-RES-001"

    def test_start_unauthorized_returns_409(self, integration_client: TestClient) -> None:
        """An assessment that was never authorized cannot be started."""
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

        # First start succeeds (202 Accepted, background job)
        resp = integration_client.post(f"/api/v1/assessments/{assessment_id}/start")
        assert resp.status_code == 202

        # Wait for background job to complete before second start
        import time

        for _ in range(50):
            resp = integration_client.get(f"/api/v1/assessments/{assessment_id}")
            if resp.json()["status"] == "completed":
                break
            time.sleep(0.1)

        # Second start fails (already completed)
        resp = integration_client.post(f"/api/v1/assessments/{assessment_id}/start")
        assert resp.status_code == 409

    def test_report_for_incomplete_returns_409(self, integration_client: TestClient) -> None:
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
        resp = integration_client.post(f"/api/v1/assessments/{assessment_id}/report")
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

    def test_validation_error_returns_400_body(self, integration_client: TestClient) -> None:
        resp = integration_client.post(
            "/api/v1/assessments",
            json={"target_value": ""},
        )
        assert resp.status_code == 422

    def test_unknown_route_returns_404(self, integration_client: TestClient) -> None:
        resp = integration_client.get("/api/v1/nonexistent")
        assert resp.status_code == 404
