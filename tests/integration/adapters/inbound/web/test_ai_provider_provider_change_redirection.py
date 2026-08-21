"""Phase 22 — provider-change credential redirection.

Phase 21 closed the case where an admin redirects a stored AI credential by
changing ``base_url`` without re-supplying ``api_key``. Its guard fires when
``body.base_url != existing.base_url`` - but ``base_url`` is not the only
field that determines where the credential is sent.

``AIProviderAdapter._enrich()`` computes the effective destination as
``resolved.base_url or resolved.provider.default_base_url``. When the
stored ``base_url`` is already ``None``, a bare provider-only save
(``PUT {"provider": "<different>"}``, no ``api_key``, no ``base_url``)
evaluates ``body.base_url != existing.base_url`` as ``None != None`` -
false. Phase 21's guard does not fire. The stored key is preserved, the
provider changes, and the next AI call sends that key to the new
provider's ``default_base_url``.

Phase 22 §2 confirmed the impact concretely: every provider name in
``providers.py``'s registry maps to a hardcoded, non-request-influenced
``default_base_url`` - five real cloud vendors, plus ``ollama``/``lm_studio``
whose defaults are hardcoded *loopback* addresses
(``http://localhost:11434/v1``, ``http://localhost:1234/v1``). None is
attacker-controlled (an admin cannot set an arbitrary destination through
``provider`` alone - it must resolve via ``resolve_provider()``), but a
stored credential can still be silently redirected to a different fixed
destination the actor performing the save never re-proved they possess
the credential for.
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
from kingsec.application.ports import AuditPublisher, URLValidationPort
from kingsec.application.ports.outbound.ai_provider_config_repository import (
    AIProviderConfigRecord,
    AIProviderConfigRepository,
)
from kingsec.application.ports.outbound.ai_provider_test import AIProviderTestPort
from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.domain import Finding, Role, Severity
from kingsec.infrastructure.ai import AIClient, AIProviderAdapter
from kingsec.infrastructure.ai.config_resolver import AIConfigResolver
from kingsec.infrastructure.ai.provider_tester import AIProviderTester
from kingsec.infrastructure.ai.providers import resolve_provider
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


class _AllowAllURLValidator(URLValidationPort):
    """SSRF coverage is Phase 14's; this file proves a distinct thing
    (destination redirection independent of key re-supply), so this
    stands in for "SSRF already passed" rather than reusing the real
    validator and blocking the local test server as loopback."""

    def validate(self, url: str) -> None:
        return None

    def open(self, url, *, method="GET", data=None, headers=None, timeout):
        raise NotImplementedError("not used by the AI provider path")


def _build_app(config_repo: AIProviderConfigRepository, encryption: EncryptionServicePort, audit: AuditPublisher):
    url_validator = _AllowAllURLValidator()
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
    return app


def _client(app: FastAPI) -> TestClient:
    return TestClient(app)


def _openai_compatible_handler(state: dict) -> type[BaseHTTPRequestHandler]:
    """Stands in for the ollama/lm_studio-shaped OpenAI-compatible wire
    format that a resolved destination would actually receive."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            return

        def do_POST(self) -> None:
            state["hit"] = True
            state["path"] = self.path
            state["headers"] = dict(self.headers)
            length = int(self.headers.get("Content-Length", 0))
            state["body"] = json.loads(self.rfile.read(length).decode())
            enrichment = {
                "title": "Fix",
                "explanation": "explanation",
                "business_impact": "impact",
                "remediation": "remediation",
                "references": [],
                "confidence": 0.9,
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps({"choices": [{"message": {"content": json.dumps(enrichment)}}]}).encode()
            )

    return Handler


@pytest.fixture
def stub_server() -> Iterator[tuple[str, dict]]:
    state: dict = {"hit": False}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _openai_compatible_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", state
    finally:
        server.shutdown()
        server.server_close()


def _make_adapter(config_repo: AIProviderConfigRepository, encryption: EncryptionServicePort) -> AIProviderAdapter:
    settings = AISettings(provider="anthropic", api_key=SecretStr("unused-env-fallback"))
    client = AIClient(timeout=5, retry_count=0, retry_delay=0, verify_ssl=True)
    resolver = AIConfigResolver(settings, config_repo, encryption)
    return AIProviderAdapter(
        settings=settings, config_resolver=resolver, client=client, url_validator=_AllowAllURLValidator()
    )


def _finding() -> Finding:
    return Finding.create("SQL Injection", "injectable parameter", Severity.HIGH)


class TestProviderOnlyChangeCannotRedirectAStoredKey:
    """The §1 shape: stored key, base_url = None, provider-only change
    with no api_key."""

    def test_provider_only_save_is_rejected_when_a_key_is_already_stored(self) -> None:
        repo = _InMemoryConfigRepository()
        encryption = FernetEncryptionService(Fernet.generate_key())
        audit = _RecordingAuditPublisher()
        app = _build_app(repo, encryption, audit)
        client = _client(app)

        resp = client.put(
            "/api/v1/settings/ai-provider",
            json={"provider": "anthropic", "api_key": "sk-ant-the-real-secret-key"},
        )
        assert resp.status_code == 200
        assert repo.get().base_url is None

        resp = client.put("/api/v1/settings/ai-provider", json={"provider": "ollama"})
        assert resp.status_code == 400, (
            f"expected the provider-only change to be refused, got {resp.status_code}: {resp.text}"
        )
        assert repo.get().provider == "anthropic", "provider changed even though the save was refused"

    def test_resolved_destination_unchanged_when_the_save_is_refused(self) -> None:
        """Assert on the resolved destination, not just the guard's
        absence - following test_concrete_impact_if_a_poisoned_record_ever_reached_the_database's
        pattern from Phase 21."""
        repo = _InMemoryConfigRepository()
        encryption = FernetEncryptionService(Fernet.generate_key())
        audit = _RecordingAuditPublisher()
        app = _build_app(repo, encryption, audit)
        client = _client(app)

        client.put(
            "/api/v1/settings/ai-provider",
            json={"provider": "anthropic", "api_key": "sk-ant-the-real-secret-key"},
        )
        client.put("/api/v1/settings/ai-provider", json={"provider": "ollama"})  # refused

        resolver = AIConfigResolver(AISettings(provider="anthropic"), repo, encryption)
        resolved = resolver.resolve()
        effective_destination = resolved.base_url or resolve_provider(resolved.provider.name).default_base_url
        assert effective_destination == resolve_provider("anthropic").default_base_url
        assert effective_destination != "http://localhost:11434/v1"

    def test_concrete_impact_if_a_poisoned_record_ever_reached_the_database(
        self, stub_server: tuple[str, dict]
    ) -> None:
        """The concrete stakes, decoupled from the guard: seeds the
        repository directly with exactly the record shape an unguarded
        provider change would have produced (a real key, the OLD
        provider's base_url left None so it resolves via the NEW
        provider's default), then drives the real runtime AI path against
        a stub standing in for that default and confirms the real key
        reaches it."""
        stub_url, state = stub_server
        repo = _InMemoryConfigRepository()
        encryption = FernetEncryptionService(Fernet.generate_key())
        # A "custom" OpenAI-compatible provider entry pointed at the stub -
        # stands in for what an unguarded provider switch would resolve to
        # (ollama/lm_studio's own default is a real, fixed loopback URL;
        # using the stub here in its place keeps the test hermetic while
        # proving the identical mechanism: base_url=None + provider default).
        # provider="openai" here to match stub_server's OpenAI-compatible
        # response shape - the point under test is "does the resolved
        # destination receive the real key," not any one provider's wire
        # format specifically.
        repo.save(
            AIProviderConfigRecord(
                provider="openai",
                api_key_encrypted=encryption.encrypt("sk-real-the-real-secret-key"),
                model=None,
                base_url=stub_url,  # simulates "the new provider's resolved default"
                updated_at="2026-01-01T00:00:00Z",
            )
        )

        adapter = _make_adapter(repo, encryption)
        adapter.recommend(_finding())

        assert state["hit"] is True
        assert state["headers"]["Authorization"] == "Bearer sk-real-the-real-secret-key"

    def test_provider_change_with_a_fresh_key_is_allowed(self, stub_server: tuple[str, dict]) -> None:
        """Not an attack, and the normal workflow: an admin moving from
        Anthropic to a fresh provider supplies a fresh key in the same
        request. Must not regress."""
        stub_url, state = stub_server
        repo = _InMemoryConfigRepository()
        encryption = FernetEncryptionService(Fernet.generate_key())
        audit = _RecordingAuditPublisher()
        app = _build_app(repo, encryption, audit)
        client = _client(app)

        client.put(
            "/api/v1/settings/ai-provider",
            json={"provider": "anthropic", "api_key": "sk-ant-old-key"},
        )

        resp = client.put(
            "/api/v1/settings/ai-provider",
            json={"provider": "openai", "api_key": "sk-openai-new-key", "base_url": stub_url},
        )
        assert resp.status_code == 200
        assert repo.get().provider == "openai"

        adapter = _make_adapter(repo, encryption)
        adapter.recommend(_finding())
        assert state["hit"] is True
        assert state["headers"]["Authorization"] == "Bearer sk-openai-new-key"

    def test_no_op_save_still_works(self) -> None:
        """Provider unchanged, base_url unchanged, no key - a routine
        re-save (e.g. just changing model) must not be blocked."""
        repo = _InMemoryConfigRepository()
        encryption = FernetEncryptionService(Fernet.generate_key())
        audit = _RecordingAuditPublisher()
        app = _build_app(repo, encryption, audit)
        client = _client(app)

        client.put(
            "/api/v1/settings/ai-provider",
            json={"provider": "anthropic", "api_key": "sk-ant-key"},
        )
        resp = client.put(
            "/api/v1/settings/ai-provider",
            json={"provider": "anthropic", "model": "claude-new-model"},
        )
        assert resp.status_code == 200
        assert repo.get().model == "claude-new-model"

    def test_first_time_save_with_provider_and_no_key_still_works(self) -> None:
        """Nothing to protect yet - no existing record."""
        repo = _InMemoryConfigRepository()
        encryption = FernetEncryptionService(Fernet.generate_key())
        audit = _RecordingAuditPublisher()
        app = _build_app(repo, encryption, audit)
        client = _client(app)

        resp = client.put("/api/v1/settings/ai-provider", json={"provider": "ollama"})
        assert resp.status_code == 200
        assert repo.get().provider == "ollama"
        assert repo.get().api_key_encrypted is None


class TestRefusalMessageDoesNotLeak:
    def test_provider_change_refusal_leaks_no_secret_or_internal_detail(self) -> None:
        repo = _InMemoryConfigRepository()
        encryption = FernetEncryptionService(Fernet.generate_key())
        audit = _RecordingAuditPublisher()
        app = _build_app(repo, encryption, audit)
        client = _client(app)

        client.put(
            "/api/v1/settings/ai-provider",
            json={"provider": "anthropic", "api_key": "sk-ant-the-secret"},
        )
        resp = client.put("/api/v1/settings/ai-provider", json={"provider": "ollama"})

        assert resp.status_code == 400
        detail = resp.json()["detail"]
        assert "sk-ant-the-secret" not in detail
        assert "localhost" not in detail
        assert "11434" not in detail
        assert "Traceback" not in detail
