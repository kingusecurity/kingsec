"""Integration tests for the AI Provider Settings routes.

Covers config precedence, key masking, and the keep-existing-key-when-
omitted save semantics through the real FastAPI routes. The /test
endpoint's real outbound HTTP call (success/failure against a genuine
provider) is deliberately NOT mocked here — it was live-verified manually
against real anthropic endpoints with both a bad and a DB-saved placeholder
key (see this session's verification notes), which is a stronger check
than a mocked transport would be. This file only covers the parts that
don't require a real network call: provider validation, precedence, and
masking.
"""

from __future__ import annotations

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
from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.domain import Role
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
