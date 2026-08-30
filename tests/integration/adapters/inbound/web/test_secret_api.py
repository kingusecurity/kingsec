"""Integration tests for the secrets admin API."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
from kingsec.application.ports.outbound.encryption_service import EncryptionServicePort
from kingsec.application.ports.outbound.secret_provider import SecretProviderPort
from kingsec.application.services.configuration_security_service import (
    ConfigurationSecurityService,
)
from kingsec.application.use_cases.delete_secret import DeleteSecret
from kingsec.application.use_cases.list_secrets import ListSecrets
from kingsec.application.use_cases.rotate_secrets import RotateSecrets
from kingsec.application.use_cases.store_secret import StoreSecret
from kingsec.bootstrap.application import Application
from kingsec.bootstrap.container import Container
from kingsec.domain import Role
from kingsec.infrastructure.config import load_settings
from kingsec.infrastructure.secrets.fernet_encryption_service import (
    FernetEncryptionService,
)

from .test_session_api import TokenClaims

_TEST_FERNET_KEY = Fernet.generate_key()


class InMemorySecretProvider(SecretProviderPort):
    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}

    def get(self, name: str) -> str | None:
        return self._secrets.get(name)

    def set(self, name: str, value: str) -> None:
        self._secrets[name] = value

    def exists(self, name: str) -> bool:
        return name in self._secrets

    def delete(self, name: str) -> None:
        self._secrets.pop(name, None)

    def list(self) -> list[str]:
        return list(self._secrets.keys())


async def override_get_current_user() -> CurrentUser:
    return CurrentUser(
        user_id="admin-1",
        username="admin",
        role=Role.ADMIN,
        claims=TokenClaims(
            user_id="admin-1",
            username="admin",
            role="admin",
            token_type="access",
            jti="admin_jti",
            issued_at=None,
            expires_at=None,
        ),
    )


@pytest.fixture
def app() -> FastAPI:
    container = Container()

    encryption_service = FernetEncryptionService(key=_TEST_FERNET_KEY)
    secret_provider = InMemorySecretProvider()

    container.register_instance(EncryptionServicePort, encryption_service)
    container.register_instance(SecretProviderPort, secret_provider)
    container.register_factory(
        StoreSecret,
        lambda c: StoreSecret(
            c.resolve(EncryptionServicePort),
            c.resolve(SecretProviderPort),
        ),
    )
    container.register_factory(
        ListSecrets,
        lambda c: ListSecrets(c.resolve(SecretProviderPort)),
    )
    container.register_factory(
        DeleteSecret,
        lambda c: DeleteSecret(c.resolve(SecretProviderPort)),
    )
    container.register_factory(
        RotateSecrets,
        lambda c: RotateSecrets(
            c.resolve(EncryptionServicePort),
            c.resolve(SecretProviderPort),
        ),
    )
    container.register_factory(
        ConfigurationSecurityService,
        lambda c: ConfigurationSecurityService(
            c.resolve(EncryptionServicePort),
            c.resolve(SecretProviderPort),
        ),
    )

    settings = load_settings()
    application = Application(
        settings=settings,
        container=container,
        exception_handlers=None,
        logger=None,
        ensure_directories=False,
    )

    fastapi_app = FastAPI()
    fastapi_app.state.kingsec_app = application
    fastapi_app.dependency_overrides[get_current_user] = override_get_current_user

    from kingsec.adapters.inbound.web.secret_routes import router

    fastapi_app.include_router(router)
    register_error_handlers(fastapi_app)

    return fastapi_app


class TestSecretAPI:
    def test_list_secrets_empty(self, app: FastAPI) -> None:
        client = TestClient(app)
        resp = client.get("/api/v1/admin/secrets")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []

    def test_store_and_list(self, app: FastAPI) -> None:
        client = TestClient(app)
        resp = client.post(
            "/api/v1/admin/secrets",
            json={"name": "db_password", "value": "MyS3cret!", "secret_type": "database_password"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "db_password"
        assert data["secret_type"] == "database_password"
        assert "masked_value" in data
        assert "secret_value" not in data

        resp2 = client.get("/api/v1/admin/secrets")
        assert resp2.status_code == 200
        items = resp2.json()["items"]
        assert len(items) == 1
        assert items[0]["name"] == "db_password"
        assert items[0]["masked_value"] != "MyS3cret!"

    def test_delete_secret(self, app: FastAPI) -> None:
        client = TestClient(app)
        client.post(
            "/api/v1/admin/secrets",
            json={"name": "temp_key", "value": "temp_value"},
        )
        resp = client.delete("/api/v1/admin/secrets/temp_key")
        assert resp.status_code == 204

        resp2 = client.get("/api/v1/admin/secrets")
        assert len(resp2.json()["items"]) == 0

    def test_secrets_status(self, app: FastAPI) -> None:
        client = TestClient(app)
        resp = client.get("/api/v1/admin/secrets/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["encryption_enabled"] is True
        assert data["provider_type"] == "InMemorySecretProvider"
        assert data["stored_secrets_count"] >= 0
        assert data["encryption_version"] == "1"

    def test_rotate_secrets(self, app: FastAPI) -> None:
        client = TestClient(app)
        client.post(
            "/api/v1/admin/secrets",
            json={"name": "key1", "value": "val1"},
        )
        resp = client.post("/api/v1/admin/secrets/rotate")
        assert resp.status_code == 200
        data = resp.json()
        assert data["reencrypted_count"] == 1
        assert len(data["new_key_fingerprint"]) == 16


class TestStoreSecretBodyMaxLengthBoundary:
    """Phase 68 / Finding KSEC-64-04: StoreSecretBody.value/.secret_type
    previously had no max_length - proves the constraint is enforced at
    the real HTTP boundary (not merely at the Pydantic-model level) and
    that a rejected request never reaches StoreSecret / the secret
    store."""

    def test_over_limit_value_is_rejected_at_the_http_boundary(self, app: FastAPI) -> None:
        client = TestClient(app)
        resp = client.post(
            "/api/v1/admin/secrets",
            json={"name": "oversized", "value": "x" * 8193},
        )
        assert resp.status_code == 422, resp.text

        # Downstream side effect did not occur: nothing was ever stored.
        listing = client.get("/api/v1/admin/secrets")
        assert listing.json()["items"] == []

    def test_over_limit_secret_type_is_rejected_at_the_http_boundary(self, app: FastAPI) -> None:
        client = TestClient(app)
        resp = client.post(
            "/api/v1/admin/secrets",
            json={"name": "oversized", "value": "v", "secret_type": "x" * 65},
        )
        assert resp.status_code == 422, resp.text
        listing = client.get("/api/v1/admin/secrets")
        assert listing.json()["items"] == []

    def test_exact_limit_value_is_accepted_and_stored(self, app: FastAPI) -> None:
        client = TestClient(app)
        resp = client.post(
            "/api/v1/admin/secrets",
            json={"name": "exact-limit", "value": "x" * 8192},
        )
        assert resp.status_code == 201, resp.text

        listing = client.get("/api/v1/admin/secrets")
        assert len(listing.json()["items"]) == 1
