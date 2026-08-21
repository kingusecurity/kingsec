"""Phase 14 — SSRF / credential-exfiltration coverage for the AI provider
settings surface.

Phase 13 disclosed that ``test_ai_provider_config()`` never validates the
user-submitted ``base_url`` before it is used to build a live outbound HTTP
request. This file proves the concrete impact (a private/internal address is
reachable, and the real API key is sent to it) and, after the Phase 14 fix,
proves the chosen policy: private/loopback addresses are refused by default,
permitted only when ``KINGSEC_AI__ALLOW_PRIVATE_BASE_URL`` is set, with
scheme rejection (``file://``) enforced unconditionally.

These tests exercise the real ``/test`` route end-to-end against a real
local HTTP server standing in for both "the legitimate local model server"
and "the internal/attacker-controlled target" - which address it represents
depends on whether the policy is expected to allow or refuse it in each test.
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
from kingsec.infrastructure.notifications.url_validator import SSRFURLValidator
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


def _build_app(*, allow_private_base_url: bool = False):
    """Same shape as test_ai_provider_routes.py's _build_app(), with the
    AIProviderTester wired to a real SSRFURLValidator so the actual SSRF
    policy under test runs, not a stub."""
    encryption = FernetEncryptionService(Fernet.generate_key())
    config_repo = _InMemoryConfigRepository()
    audit = _RecordingAuditPublisher()
    url_validator = SSRFURLValidator(allow_private=allow_private_base_url)
    tester: AIProviderTestPort = AIProviderTester(url_validator)
    settings = Settings(ai=AISettings(provider="anthropic"))

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


def _anthropic_handler(state: dict) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            return

        def do_POST(self) -> None:
            state["hit"] = True
            state["path"] = self.path
            state["headers"] = dict(self.headers)
            length = int(self.headers.get("Content-Length", 0))
            state["body"] = json.loads(self.rfile.read(length).decode())
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"content": [{"type": "text", "text": "OK"}]}).encode())

    return Handler


@pytest.fixture
def local_stub_server() -> Iterator[tuple[str, dict]]:
    """A real server on 127.0.0.1 - the address itself is what's under test:
    private/loopback addresses must be refused by default and permitted only
    under the opt-in flag."""
    state: dict = {"hit": False}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _anthropic_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", state
    finally:
        server.shutdown()
        server.server_close()


class TestPrivateBaseUrlDefaultPolicy:
    """Required coverage: a base_url pointing at a blocked (private/loopback)
    address is refused by the chosen policy, at /test, by default."""

    def test_loopback_base_url_refused_by_default(self, local_stub_server: tuple[str, dict]) -> None:
        base_url, state = local_stub_server
        app, _repo, _audit = _build_app(allow_private_base_url=False)
        resp = _client(app).post(
            "/api/v1/settings/ai-provider/test",
            json={"provider": "anthropic", "api_key": "sk-ant-should-not-be-sent", "base_url": base_url},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is False
        # The concrete impact: the request must never have reached the
        # target at all when refused - not just "reported a failure".
        assert state["hit"] is False, "blocked base_url was still contacted"

    def test_no_api_key_transmitted_to_a_refused_destination(self, local_stub_server: tuple[str, dict]) -> None:
        """Phase 13 Sec 3.3's credential-exfiltration concern, proven
        directly: assert on what the stub server actually received (nothing)
        rather than only on the route's response."""
        base_url, state = local_stub_server
        app, _repo, _audit = _build_app(allow_private_base_url=False)
        _client(app).post(
            "/api/v1/settings/ai-provider/test",
            json={"provider": "anthropic", "api_key": "sk-ant-the-real-secret-key", "base_url": base_url},
        )
        assert state["hit"] is False
        assert "headers" not in state  # the server never even parsed a request


class TestPrivateBaseUrlOptInFlag:
    """Required coverage: the permitted case still works. Proves the fix
    does not break local-first / local-model-server deployments."""

    def test_loopback_base_url_allowed_when_flag_enabled(self, local_stub_server: tuple[str, dict]) -> None:
        base_url, state = local_stub_server
        app, _repo, _audit = _build_app(allow_private_base_url=True)
        resp = _client(app).post(
            "/api/v1/settings/ai-provider/test",
            json={"provider": "anthropic", "api_key": "sk-ant-local-key", "base_url": base_url},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is True
        assert state["hit"] is True
        assert state["headers"]["x-api-key"] == "sk-ant-local-key"

    def test_loopback_base_url_refused_when_flag_disabled(self, local_stub_server: tuple[str, dict]) -> None:
        """Same target, opposite flag state - isolates the flag as the
        deciding factor rather than anything else about the request."""
        base_url, state = local_stub_server
        app, _repo, _audit = _build_app(allow_private_base_url=False)
        resp = _client(app).post(
            "/api/v1/settings/ai-provider/test",
            json={"provider": "anthropic", "api_key": "sk-ant-local-key", "base_url": base_url},
        )
        assert resp.json()["success"] is False
        assert state["hit"] is False


class TestSchemeRejection:
    def test_file_scheme_refused(self) -> None:
        app, _repo, _audit = _build_app(allow_private_base_url=False)
        resp = _client(app).post(
            "/api/v1/settings/ai-provider/test",
            json={"provider": "anthropic", "api_key": "sk-ant-x", "base_url": "file:///etc/passwd"},
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is False

    def test_file_scheme_refused_even_with_private_access_enabled(self) -> None:
        """The opt-in flag permits private *network* addresses, not
        arbitrary schemes - file:// must stay blocked unconditionally."""
        app, _repo, _audit = _build_app(allow_private_base_url=True)
        resp = _client(app).post(
            "/api/v1/settings/ai-provider/test",
            json={"provider": "anthropic", "api_key": "sk-ant-x", "base_url": "file:///etc/passwd"},
        )
        assert resp.json()["success"] is False


class TestCloudMetadataStaysBlocked:
    """169.254.169.254 (AWS/GCP/Azure instance metadata) must remain blocked
    even when the local-model-server opt-in flag is enabled - it is a
    link-local address, not a loopback/RFC1918 one, and permitting it would
    defeat the entire point of blocking cloud-metadata SSRF."""

    def test_link_local_metadata_address_refused_even_with_flag_enabled(self) -> None:
        app, _repo, _audit = _build_app(allow_private_base_url=True)
        resp = _client(app).post(
            "/api/v1/settings/ai-provider/test",
            json={"provider": "anthropic", "api_key": "sk-ant-x", "base_url": "http://169.254.169.254/"},
        )
        assert resp.json()["success"] is False
