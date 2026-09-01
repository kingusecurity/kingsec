"""Phase 21 — credential-exfiltration coverage for the AI provider settings
surface (Phase 14 §5, closed here).

Phase 14 fixed *where* the AI provider path can be pointed (SSRF: no
loopback, no RFC1918, no metadata endpoints, opt-in for local model
servers). It explicitly did not address that a **public** destination
passes every one of those checks and still receives whatever API key the
request carries.

Phase 21 §2 established the real vector precisely: ``save_ai_provider_config()``
preserves a previously-saved, encrypted API key whenever the request omits
one, but writes ``base_url`` straight from the request body with no such
preservation. So one admin can save a real key against the real provider,
and a *second* admin - or the same admin's compromised session, which never
learned the plaintext key (GET only ever returns a masked last-4) - can
later submit a save containing *only* a new ``base_url``. The next real AI
call (``AIProviderAdapter._enrich()``, via ``AIConfigResolver``) resolves
the stored key and the new ``base_url`` from the same database row and
sends the real credential to the new destination. SSRF protection
(``URLValidationPort``) never blocks this, because a public
attacker-controlled domain passes every private-address check by design.

The ``/test`` endpoint's equivalent sub-question (base_url supplied, api_key
omitted, falling back to a stored key) is *not* real:
``TestAIProviderConfigBody.api_key`` is a required, non-nullable Pydantic
field, so that specific request shape is rejected before the route body
ever runs. No test is needed to prove a negative Pydantic already enforces;
``TestBaseUrlOnlyChangeIsRejectedAtTestEndpoint`` below confirms it anyway,
for completeness against the exact combination §2.1 named.
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


class _AllowAllURLValidator(URLValidationPort):
    """A stand-in for "SSRF protection already passed" - the credential-
    exfiltration vector is specifically about a *public*, non-blocked
    destination (Phase 14 §5: "https://attacker.example.com passes every
    private-IP check"). Using the real SSRFURLValidator here would block
    the local test server as a loopback address and conflate SSRF
    coverage (already proven in test_ai_provider_ssrf.py) with the
    distinct thing this file proves."""

    def validate(self, url: str) -> None:
        return None

    def open(self, url, *, method="GET", data=None, headers=None, timeout):
        raise NotImplementedError("not used by the AI provider path")


def _build_app(
    config_repo: AIProviderConfigRepository,
    encryption: EncryptionServicePort,
    audit: AuditPublisher,
    url_validator: URLValidationPort | None = None,
    *,
    allow_private: bool = True,
):
    """Same shape as test_ai_provider_ssrf.py's _build_app(), parameterised
    on a shared repo/encryption pair so a test can save through the route
    and then resolve through AIConfigResolver against the same store.

    allow_private (KSEC-85-01) configures AIClient's OWN resolve-and-pin
    step, independent of url_validator - AIClient no longer merely trusts
    an upfront URLValidationPort check, so a caller using a real
    SSRFURLValidator (to test the refusal policy itself) must pass the
    matching allow_private value explicitly; every other caller here uses
    the default True, matching _AllowAllURLValidator's "SSRF already
    passed" stand-in purpose.
    """
    url_validator = url_validator or _AllowAllURLValidator()
    tester: AIProviderTestPort = AIProviderTester(url_validator, allow_private=allow_private)
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
            enrichment_text = json.dumps(
                {
                    "title": "Fix",
                    "explanation": "explanation",
                    "business_impact": "impact",
                    "remediation": "remediation",
                    "references": [],
                    "confidence": 0.9,
                }
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"content": [{"type": "text", "text": enrichment_text}]}).encode())

    return Handler


@pytest.fixture
def attacker_server() -> Iterator[tuple[str, dict]]:
    """A real server standing in for an attacker's public endpoint - the
    address itself is a normal public loopback-free host from the
    validator's point of view; SSRF protection is not what's under test
    here, and none of these tests expect it to fire."""
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


def _make_adapter(
    config_repo: AIProviderConfigRepository,
    encryption: EncryptionServicePort,
    url_validator: URLValidationPort | None = None,
    *,
    allow_private: bool = True,
) -> AIProviderAdapter:
    """Wire a real AIProviderAdapter against the same repo/encryption a
    save route used, so the next real AI call resolves whatever that
    route actually persisted - not a stand-in.

    allow_private (KSEC-85-01): see _build_app()'s docstring - must match
    whatever policy url_validator represents when a caller passes a real
    SSRFURLValidator instead of _AllowAllURLValidator.
    """
    settings = AISettings(provider="anthropic", api_key=SecretStr("unused-env-fallback"))
    client = AIClient(timeout=5, retry_count=0, retry_delay=0, verify_ssl=True, allow_private=allow_private)
    resolver = AIConfigResolver(settings, config_repo, encryption)
    return AIProviderAdapter(
        settings=settings,
        config_resolver=resolver,
        client=client,
        url_validator=url_validator or _AllowAllURLValidator(),
    )


def _finding() -> Finding:
    return Finding.create("SQL Injection", "injectable parameter", Severity.HIGH)


class TestBaseUrlOnlyChangeCannotRedirectAStoredKey:
    """Phase 21 §2.2's vector: a stored key must never be sent to a
    destination introduced by a save that never re-supplied the key."""

    def test_base_url_only_save_is_rejected_when_a_key_is_already_stored(
        self, attacker_server: tuple[str, dict]
    ) -> None:
        attacker_url, state = attacker_server
        repo = _InMemoryConfigRepository()
        encryption = FernetEncryptionService(Fernet.generate_key())
        audit = _RecordingAuditPublisher()
        app = _build_app(repo, encryption, audit)
        client = _client(app)

        # Legitimate first save: a real admin sets a real key.
        resp = client.put(
            "/api/v1/settings/ai-provider",
            json={"provider": "anthropic", "api_key": "sk-ant-the-real-secret-key"},
        )
        assert resp.status_code == 200
        assert repo.get().api_key_encrypted is not None

        # A second save changes only base_url - no api_key in the body.
        resp = client.put(
            "/api/v1/settings/ai-provider",
            json={"provider": "anthropic", "base_url": attacker_url},
        )
        assert resp.status_code == 400, (
            f"expected the base_url-only change to be refused, got {resp.status_code}: {resp.text}"
        )
        assert repo.get().base_url != attacker_url, "base_url changed even though the save was refused"
        # Never even attempted - the guard fires before any outbound call.
        assert state["hit"] is False

    def test_concrete_impact_if_a_poisoned_record_ever_reached_the_database(
        self, attacker_server: tuple[str, dict]
    ) -> None:
        """Phase 14 §5's evidentiary standard, applied here: prove the
        stakes concretely via the actual receiving server, not the guard
        in isolation. Seeds the repository directly (bypassing the save
        route and its guard entirely) with exactly the record shape the
        vulnerability would have produced, then drives the real runtime
        AI path and confirms it sends the real key to that base_url -
        demonstrating why the save-time guard above is the only place
        this can be stopped, not something the runtime path itself
        should (or safely could) second-guess."""
        attacker_url, state = attacker_server
        repo = _InMemoryConfigRepository()
        encryption = FernetEncryptionService(Fernet.generate_key())
        repo.save(
            AIProviderConfigRecord(
                provider="anthropic",
                api_key_encrypted=encryption.encrypt("sk-ant-the-real-secret-key"),
                model=None,
                base_url=attacker_url,
                updated_at="2026-01-01T00:00:00Z",
            )
        )

        adapter = _make_adapter(repo, encryption)
        adapter.recommend(_finding())

        assert state["hit"] is True
        assert state["headers"]["x-api-key"] == "sk-ant-the-real-secret-key"

    def test_base_url_change_with_a_fresh_key_is_allowed(self, attacker_server: tuple[str, dict]) -> None:
        """Not an attack: the admin who chooses the new destination also
        supplies the credential for it in the same request."""
        new_url, state = attacker_server
        repo = _InMemoryConfigRepository()
        encryption = FernetEncryptionService(Fernet.generate_key())
        audit = _RecordingAuditPublisher()
        app = _build_app(repo, encryption, audit)
        client = _client(app)

        client.put("/api/v1/settings/ai-provider", json={"provider": "anthropic", "api_key": "sk-ant-old-key"})

        resp = client.put(
            "/api/v1/settings/ai-provider",
            json={"provider": "anthropic", "api_key": "sk-ant-new-key", "base_url": new_url},
        )
        assert resp.status_code == 200
        assert repo.get().base_url == new_url

        adapter = _make_adapter(repo, encryption)
        adapter.recommend(_finding())
        assert state["hit"] is True
        assert state["headers"]["x-api-key"] == "sk-ant-new-key"

    def test_base_url_only_save_allowed_when_no_key_is_stored_yet(self, attacker_server: tuple[str, dict]) -> None:
        """Not an attack either: nothing is being redirected because
        nothing secret was ever stored to protect."""
        base_url, _state = attacker_server
        repo = _InMemoryConfigRepository()
        encryption = FernetEncryptionService(Fernet.generate_key())
        audit = _RecordingAuditPublisher()
        app = _build_app(repo, encryption, audit)
        client = _client(app)

        resp = client.put("/api/v1/settings/ai-provider", json={"provider": "anthropic", "base_url": base_url})
        assert resp.status_code == 200
        assert repo.get().base_url == base_url
        assert repo.get().api_key_encrypted is None

    def test_save_with_unchanged_base_url_and_no_key_still_works(self, attacker_server: tuple[str, dict]) -> None:
        """A routine "just update the model" save, base_url untouched,
        must not be blocked by this fix."""
        base_url, _state = attacker_server
        repo = _InMemoryConfigRepository()
        encryption = FernetEncryptionService(Fernet.generate_key())
        audit = _RecordingAuditPublisher()
        app = _build_app(repo, encryption, audit)
        client = _client(app)

        client.put(
            "/api/v1/settings/ai-provider",
            json={"provider": "anthropic", "api_key": "sk-ant-key", "base_url": base_url},
        )
        resp = client.put(
            "/api/v1/settings/ai-provider",
            json={"provider": "anthropic", "model": "claude-new-model", "base_url": base_url},
        )
        assert resp.status_code == 200
        assert repo.get().model == "claude-new-model"
        assert repo.get().base_url == base_url


class TestLocalModelServerStillWorks:
    """Proves the fix does not break Phase 14's local-first accommodation:
    a real SSRFURLValidator(allow_private=True), a real local base_url +
    api_key saved together in one request (the legitimate shape - the
    admin choosing the destination also supplies the credential for it),
    end to end through save and the real runtime AI call."""

    def test_local_base_url_saved_with_key_together_still_reaches_the_server(
        self, attacker_server: tuple[str, dict]
    ) -> None:
        local_url, state = attacker_server  # a real 127.0.0.1 server this time
        repo = _InMemoryConfigRepository()
        encryption = FernetEncryptionService(Fernet.generate_key())
        audit = _RecordingAuditPublisher()
        validator = SSRFURLValidator(allow_private=True)
        app = _build_app(repo, encryption, audit, url_validator=validator)
        client = _client(app)

        resp = client.put(
            "/api/v1/settings/ai-provider",
            json={"provider": "anthropic", "api_key": "sk-ant-local-key", "base_url": local_url},
        )
        assert resp.status_code == 200
        assert repo.get().base_url == local_url

        adapter = _make_adapter(repo, encryption, url_validator=validator)
        adapter.recommend(_finding())
        assert state["hit"] is True
        assert state["headers"]["x-api-key"] == "sk-ant-local-key"

    def test_local_base_url_refused_without_the_opt_in_flag(self, attacker_server: tuple[str, dict]) -> None:
        """Same save, opposite flag state - Phase 14's policy still applies
        unchanged; this fix only ever adds a check, never removes one."""
        local_url, state = attacker_server
        repo = _InMemoryConfigRepository()
        encryption = FernetEncryptionService(Fernet.generate_key())
        audit = _RecordingAuditPublisher()
        validator = SSRFURLValidator(allow_private=False)
        app = _build_app(repo, encryption, audit, url_validator=validator, allow_private=False)
        client = _client(app)

        resp = client.put(
            "/api/v1/settings/ai-provider",
            json={"provider": "anthropic", "api_key": "sk-ant-local-key", "base_url": local_url},
        )
        assert resp.status_code == 200  # the save itself has never been SSRF-gated (§4.1)
        assert repo.get().base_url == local_url

        adapter = _make_adapter(repo, encryption, url_validator=validator, allow_private=False)
        with pytest.raises(Exception):
            adapter.recommend(_finding())
        assert state["hit"] is False


class TestBaseUrlOnlyChangeIsRejectedAtTestEndpoint:
    """§2.1's exact combination (base_url supplied, api_key omitted) is
    already impossible at /test - TestAIProviderConfigBody.api_key is a
    required field. Confirmed directly rather than left as an inference."""

    def test_test_endpoint_requires_api_key(self) -> None:
        repo = _InMemoryConfigRepository()
        encryption = FernetEncryptionService(Fernet.generate_key())
        audit = _RecordingAuditPublisher()
        app = _build_app(repo, encryption, audit)

        resp = _client(app).post(
            "/api/v1/settings/ai-provider/test",
            json={"provider": "anthropic", "base_url": "http://example.com"},
        )
        assert resp.status_code == 422


class TestRefusalMessageDoesNotLeak:
    def test_refusal_message_contains_no_stored_secret_or_internal_detail(
        self, attacker_server: tuple[str, dict]
    ) -> None:
        attacker_url, _state = attacker_server
        repo = _InMemoryConfigRepository()
        encryption = FernetEncryptionService(Fernet.generate_key())
        audit = _RecordingAuditPublisher()
        app = _build_app(repo, encryption, audit)
        client = _client(app)

        client.put("/api/v1/settings/ai-provider", json={"provider": "anthropic", "api_key": "sk-ant-the-secret"})
        resp = client.put("/api/v1/settings/ai-provider", json={"provider": "anthropic", "base_url": attacker_url})

        assert resp.status_code == 400
        detail = resp.json()["detail"]
        assert "sk-ant-the-secret" not in detail
        assert "Traceback" not in detail
