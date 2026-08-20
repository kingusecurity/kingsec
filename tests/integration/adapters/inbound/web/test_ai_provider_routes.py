"""Integration tests for the AI Provider Settings routes.

Covers config precedence, key masking, and the keep-existing-key-when-
omitted save semantics through the real FastAPI routes.

Phase 13: the /test endpoint's real outbound HTTP call previously had zero
automated coverage of its success/failure network-calling logic (the file's
prior docstring said this was deliberately live-verified manually instead -
see git history). That is exactly the code this phase moves behind a port,
so TestTestConnectionAgainstRealServer below adds real characterization
coverage BEFORE the refactor, using a real local HTTP server (matching
tests/integration/ai/conftest.py's own established pattern) rather than a
mock, so the real request-building/response-parsing path is exercised.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from kingsec.adapters.inbound.web.ai_provider_routes import router
from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
from kingsec.application.ports import AuditPublisher
from kingsec.application.ports.outbound.ai_provider_config_repository import (
    AIProviderConfigRecord,
    AIProviderConfigRepository,
)
from kingsec.application.ports.outbound.ai_provider_test import AIProviderTestPort
from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.domain import Role
from kingsec.infrastructure.ai.provider_tester import AIProviderTester
from kingsec.infrastructure.config import Settings
from kingsec.infrastructure.config.models import AISettings
from kingsec.infrastructure.secrets.fernet_encryption_service import FernetEncryptionService


class _InMemoryConfigRepository(AIProviderConfigRepository):
    def __init__(self) -> None:
        self._record: AIProviderConfigRecord | None = None

    def get(self):
        return self._record

    def save(self, record: AIProviderConfigRecord) -> None:
        self._record = record


class _RecordingAuditPublisher(AuditPublisher):
    def __init__(self) -> None:
        self.entries = []

    def record(self, entry) -> None:
        self.entries.append(entry)


def _build_app(*, ai_settings: AISettings | None = None):
    encryption = FernetEncryptionService(Fernet.generate_key())
    config_repo = _InMemoryConfigRepository()
    audit = _RecordingAuditPublisher()
    # The real implementation, not a stub - these tests exist specifically
    # to exercise the real provider-resolution/network-calling path (see
    # module docstring), which is exactly what moved behind this port.
    tester: AIProviderTestPort = AIProviderTester()
    settings = Settings(ai=ai_settings or AISettings(provider="anthropic"))

    app = FastAPI()

    class _StubApp:
        def __init__(self) -> None:
            self.settings = settings

        def resolve(self, service_type: type):
            if service_type is AIProviderConfigRepository:
                return config_repo
            if service_type is EncryptionServicePort:
                return encryption
            if service_type is AuditPublisher:
                return audit
            if service_type is AIProviderTestPort:
                return tester
            raise ValueError(f"Unknown service: {service_type}")

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    admin_user = CurrentUser(user_id="admin-1", username="admin", role=Role.ADMIN)
    app.dependency_overrides[get_current_user] = lambda: admin_user

    app.include_router(router)
    return app, config_repo, audit


def _client(app: FastAPI) -> TestClient:
    return TestClient(app)


class TestGetConfig:
    def test_nothing_configured_reports_source_none(self) -> None:
        app, _repo, _audit = _build_app(ai_settings=AISettings(provider="anthropic", api_key=None))
        resp = _client(app).get("/api/v1/settings/ai-provider")
        assert resp.status_code == 200
        body = resp.json()
        assert body["source"] == "none"
        assert body["api_key_masked"] is None

    def test_env_key_reports_source_environment_masked(self) -> None:
        app, _repo, _audit = _build_app(
            ai_settings=AISettings(provider="anthropic", api_key=SecretStr("env-secret-key-9999"))
        )
        resp = _client(app).get("/api/v1/settings/ai-provider")
        body = resp.json()
        assert body["source"] == "environment"
        assert body["api_key_masked"] == "********9999"
        assert "env-secret-key" not in resp.text


class TestSaveConfig:
    def test_save_then_get_shows_masked_key_and_database_source(self) -> None:
        app, repo, audit = _build_app()
        client = _client(app)

        save_resp = client.put(
            "/api/v1/settings/ai-provider",
            json={"provider": "anthropic", "api_key": "sk-ant-real-secret-abcd", "model": "claude-x"},
        )
        assert save_resp.status_code == 200

        get_resp = client.get("/api/v1/settings/ai-provider")
        body = get_resp.json()
        assert body["source"] == "database"
        assert body["api_key_masked"] == "********abcd"
        assert "sk-ant-real-secret" not in get_resp.text

        # The plaintext key is never persisted anywhere.
        assert repo.get().api_key_encrypted != b"sk-ant-real-secret-abcd"
        assert len(audit.entries) == 1
        assert audit.entries[0].action.value == "ai_provider_configured"

    def test_db_config_overrides_env_key(self) -> None:
        app, _repo, _audit = _build_app(
            ai_settings=AISettings(provider="anthropic", api_key=SecretStr("env-key-should-lose"))
        )
        client = _client(app)
        client.put("/api/v1/settings/ai-provider", json={"provider": "openai", "api_key": "sk-db-key-wins-1234"})

        body = client.get("/api/v1/settings/ai-provider").json()
        assert body["source"] == "database"
        assert body["provider"] == "openai"
        assert body["api_key_masked"] == "********1234"

    def test_omitting_api_key_keeps_existing_saved_key(self) -> None:
        app, _repo, _audit = _build_app()
        client = _client(app)
        client.put("/api/v1/settings/ai-provider", json={"provider": "anthropic", "api_key": "sk-original-key-0001"})

        # Change the model without retyping the key.
        resp = client.put("/api/v1/settings/ai-provider", json={"provider": "anthropic", "model": "claude-new"})
        assert resp.status_code == 200

        body = client.get("/api/v1/settings/ai-provider").json()
        assert body["model"] == "claude-new"
        assert body["api_key_masked"] == "********0001"  # unchanged

    def test_unsupported_provider_rejected(self) -> None:
        app, _repo, _audit = _build_app()
        resp = _client(app).put(
            "/api/v1/settings/ai-provider", json={"provider": "not-a-real-provider", "api_key": "x"}
        )
        assert resp.status_code == 400


class TestTestConnection:
    def test_unsupported_provider_fails_without_any_network_call(self) -> None:
        app, _repo, _audit = _build_app()
        resp = _client(app).post(
            "/api/v1/settings/ai-provider/test",
            json={"provider": "not-a-real-provider", "api_key": "x"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is False


def _anthropic_handler(state: dict) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:  # silence server logging
            return

        def do_POST(self) -> None:
            state["path"] = self.path
            state["headers"] = dict(self.headers)
            length = int(self.headers.get("Content-Length", 0))
            state["body"] = json.loads(self.rfile.read(length).decode())

            if state["mode"] == "unauthorized":
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": {"message": "invalid x-api-key"}}).encode())
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"content": [{"type": "text", "text": "OK"}]}).encode())

    return Handler


@pytest.fixture
def anthropic_stub_server() -> Iterator[tuple[str, dict]]:
    """A real local server shaped like Anthropic's /v1/messages endpoint.

    Phase 13: characterization coverage for test_ai_provider_config()'s
    real network-calling path, written BEFORE the port refactor. Uses a
    real socket server (this codebase's established pattern for AI-client
    tests - see tests/integration/ai/conftest.py) rather than a mock, and
    reaches it via the route's own body.base_url override - no monkeypatch
    of AIClient or the route needed.
    """
    state: dict = {"mode": "ok"}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _anthropic_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", state
    finally:
        server.shutdown()
        server.server_close()


class TestTestConnectionAgainstRealServer:
    """Characterization tests for the /test endpoint's real HTTP call,
    written before Phase 13's port refactor. Exercises the actual
    resolve_provider -> build_endpoint/headers/payload -> AIClient.post_json
    -> extract_text path end to end against a real local server - the
    exact code path this phase moves behind a port. Must pass, unmodified,
    both before and after the refactor.
    """

    def test_successful_connection(self, anthropic_stub_server: tuple[str, dict]) -> None:
        base_url, state = anthropic_stub_server
        app, _repo, _audit = _build_app()
        resp = _client(app).post(
            "/api/v1/settings/ai-provider/test",
            json={"provider": "anthropic", "api_key": "sk-ant-test-key", "base_url": base_url},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is True
        assert "anthropic" in body["message"]
        # Confirms the real request-building path ran: correct endpoint,
        # correct auth header, api key never logged/echoed anywhere.
        assert state["path"] == "/v1/messages"
        assert state["headers"]["x-api-key"] == "sk-ant-test-key"
        assert "sk-ant-test-key" not in resp.text

    def test_failed_connection_reports_failure_without_500(self, anthropic_stub_server: tuple[str, dict]) -> None:
        base_url, state = anthropic_stub_server
        state["mode"] = "unauthorized"
        app, _repo, audit = _build_app()
        resp = _client(app).post(
            "/api/v1/settings/ai-provider/test",
            json={"provider": "anthropic", "api_key": "sk-ant-bad-key", "base_url": base_url},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is False
        assert len(body["message"]) > 0
        # A failed test is audited (AI_PROVIDER_TEST_FAILED), unlike the
        # success path above which records nothing for /test.
        assert len(audit.entries) == 1
        assert audit.entries[0].action.value == "ai_provider_test_failed"

    def test_default_model_used_when_body_omits_one(self, anthropic_stub_server: tuple[str, dict]) -> None:
        base_url, state = anthropic_stub_server
        app, _repo, _audit = _build_app()
        resp = _client(app).post(
            "/api/v1/settings/ai-provider/test",
            json={"provider": "anthropic", "api_key": "sk-ant-test-key", "base_url": base_url},
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        assert state["body"]["model"] == "claude-sonnet-4-5"  # default_model_for("anthropic")
