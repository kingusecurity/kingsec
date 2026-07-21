"""Integration test: API key lifecycle via HTTP endpoints."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application import (
    CreateApiKey,
    ListApiKeys,
    Login,
    RefreshToken,
    RegisterUser,
    RevokeApiKey,
    RotateApiKey,
    ValidateApiKey,
)
from kingsec.application.auth import AuthorizationService
from kingsec.application.ports import ApiKeyHasher, ApiKeyRepository, TokenService
from kingsec.domain.api_key import ApiKey

from .test_auth_integration import StubHasher, StubTokenService, StubUserRepo


class StubApiKeyHasher(ApiKeyHasher):
    def hash(self, plaintext_key: str) -> str:
        return f"hashed:{plaintext_key}"

    def verify(self, plaintext_key: str, key_hash: str) -> bool:
        return key_hash == f"hashed:{plaintext_key}"


class StubApiKeyRepository(ApiKeyRepository):
    def __init__(self) -> None:
        self._keys: dict[str, ApiKey] = {}

    def find_by_id(self, api_key_id: str) -> ApiKey | None:
        return self._keys.get(api_key_id)

    def find_by_user_id(self, user_id: str, limit: int = 50, offset: int = 0) -> list[ApiKey]:
        items = [k for k in self._keys.values() if k.user_id == user_id]
        items.sort(key=lambda k: k.created_at, reverse=True)
        return items[offset : offset + limit]

    def save(self, key: ApiKey) -> None:
        self._keys[key.id] = key

    def delete(self, api_key_id: str) -> None:
        self._keys.pop(api_key_id, None)

    def count_by_user(self, user_id: str) -> int:
        return sum(1 for k in self._keys.values() if k.user_id == user_id)


def _build_app() -> tuple[FastAPI, StubTokenService, StubUserRepo, StubApiKeyRepository, StubApiKeyHasher]:
    """Build a FastAPI app with stubbed auth and API key dependencies."""
    token_service = StubTokenService()
    user_repo = StubUserRepo()
    hasher = StubHasher()
    key_repo = StubApiKeyRepository()
    key_hasher = StubApiKeyHasher()

    app = FastAPI()

    class _StubApp:
        def resolve(self, service_type: type):
            from kingsec.application.ports import PasswordHasher, UserRepository
            if service_type == TokenService:
                return token_service
            if service_type == UserRepository:
                return user_repo
            if service_type == PasswordHasher:
                return hasher
            if service_type == AuthorizationService:
                return AuthorizationService()
            if service_type == ApiKeyRepository:
                return key_repo
            if service_type == ApiKeyHasher:
                return key_hasher
            if service_type == RegisterUser:
                return RegisterUser(user_repo, hasher)
            if service_type == Login:
                return Login(user_repo, hasher, token_service)
            if service_type == RefreshToken:
                return RefreshToken(user_repo, token_service)
            if service_type == CreateApiKey:
                return CreateApiKey(key_repo, key_hasher)
            if service_type == ListApiKeys:
                return ListApiKeys(key_repo)
            if service_type == RevokeApiKey:
                return RevokeApiKey(key_repo)
            if service_type == RotateApiKey:
                return RotateApiKey(key_repo, key_hasher)
            if service_type == ValidateApiKey:
                return ValidateApiKey(key_repo, key_hasher)
            raise ValueError(f"Unknown service: {service_type}")

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router

    register_error_handlers(app)
    app.include_router(router)

    return app, token_service, user_repo, key_repo, key_hasher


class TestApiKeyIntegration:
    """Full API key lifecycle tests."""

    def _register_and_login(self, client: TestClient, token_service: StubTokenService, user_repo: StubUserRepo, username: str = "testuser") -> str:
        """Helper: register a user and return an access token."""
        register_resp = client.post(
            "/api/v1/auth/register",
            json={
                "username": username,
                "email": f"{username}@example.com",
                "password": "SecurePass1",
                "role": "analyst",
            },
        )
        assert register_resp.status_code == 201

        login_resp = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": "SecurePass1"},
        )
        assert login_resp.status_code == 200
        return login_resp.json()["access_token"]

    def test_create_and_list_api_keys(self) -> None:
        app, token_service, user_repo, _key_repo, _key_hasher = _build_app()
        client = TestClient(app)

        token = self._register_and_login(client, token_service, user_repo)

        # Create an API key.
        create_resp = client.post(
            "/api/v1/apikeys",
            json={"name": "CI/CD Pipeline", "scope": "read_only"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert create_resp.status_code == 201
        body = create_resp.json()
        assert body["name"] == "CI/CD Pipeline"
        assert body["scope"] == "read_only"
        assert body["plaintext_key"].startswith("ks_")
        assert body["api_key_id"] is not None

        # List API keys.
        list_resp = client.get(
            "/api/v1/apikeys",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert list_resp.status_code == 200
        list_body = list_resp.json()
        assert list_body["total"] >= 1
        assert any(item["api_key_id"] == body["api_key_id"] for item in list_body["items"])

    def test_use_api_key_for_authentication(self) -> None:
        app, token_service, user_repo, _key_repo, _key_hasher = _build_app()
        client = TestClient(app)

        token = self._register_and_login(client, token_service, user_repo)

        # Create an API key.
        create_resp = client.post(
            "/api/v1/apikeys",
            json={"name": "My Key", "scope": "read_only"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert create_resp.status_code == 201
        plaintext_key = create_resp.json()["plaintext_key"]

        # Use the API key to authenticate (via X-API-Key header).
        list_resp = client.get(
            "/api/v1/apikeys/me",
            headers={"X-API-Key": plaintext_key},
        )
        assert list_resp.status_code == 200
        body = list_resp.json()
        assert body["scope"] == "read_only"
        assert body["status"] == "active"

    def test_api_key_via_bearer_header(self) -> None:
        app, token_service, user_repo, _key_repo, _key_hasher = _build_app()
        client = TestClient(app)

        token = self._register_and_login(client, token_service, user_repo)

        create_resp = client.post(
            "/api/v1/apikeys",
            json={"name": "Bearer Key", "scope": "full_access"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert create_resp.status_code == 201
        plaintext_key = create_resp.json()["plaintext_key"]

        list_resp = client.get(
            "/api/v1/apikeys/me",
            headers={"Authorization": f"Bearer {plaintext_key}"},
        )
        assert list_resp.status_code == 200
        body = list_resp.json()
        assert body["scope"] == "full_access"

    def test_revoke_api_key(self) -> None:
        app, token_service, user_repo, _key_repo, _key_hasher = _build_app()
        client = TestClient(app)

        token = self._register_and_login(client, token_service, user_repo)

        create_resp = client.post(
            "/api/v1/apikeys",
            json={"name": "To Revoke", "scope": "read_only"},
            headers={"Authorization": f"Bearer {token}"},
        )
        key_id = create_resp.json()["api_key_id"]

        revoke_resp = client.delete(
            f"/api/v1/apikeys/{key_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert revoke_resp.status_code == 204

        # Verify the key is revoked (should fail auth).
        plaintext_key = create_resp.json()["plaintext_key"]
        me_resp = client.get(
            "/api/v1/apikeys/me",
            headers={"X-API-Key": plaintext_key},
        )
        assert me_resp.status_code == 401

    def test_rotate_api_key(self) -> None:
        app, token_service, user_repo, _key_repo, _key_hasher = _build_app()
        client = TestClient(app)

        token = self._register_and_login(client, token_service, user_repo)

        create_resp = client.post(
            "/api/v1/apikeys",
            json={"name": "To Rotate", "scope": "full_access"},
            headers={"Authorization": f"Bearer {token}"},
        )
        key_id = create_resp.json()["api_key_id"]
        old_plaintext = create_resp.json()["plaintext_key"]

        rotate_resp = client.post(
            f"/api/v1/apikeys/{key_id}/rotate",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert rotate_resp.status_code == 200
        new_plaintext = rotate_resp.json()["plaintext_key"]
        assert new_plaintext != old_plaintext
        assert new_plaintext.startswith("ks_")

        # Old key should fail.
        old_resp = client.get(
            "/api/v1/apikeys/me",
            headers={"X-API-Key": old_plaintext},
        )
        assert old_resp.status_code == 401

        # New key should work.
        new_resp = client.get(
            "/api/v1/apikeys/me",
            headers={"X-API-Key": new_plaintext},
        )
        if new_resp.status_code != 200:
            print("DEBUG rotate new key response:", new_resp.status_code, new_resp.text)
        assert new_resp.status_code == 200
        assert new_resp.json()["scope"] == "full_access"

    def test_missing_api_key_returns_401(self) -> None:
        app, _token_service, _user_repo, _key_repo, _key_hasher = _build_app()
        client = TestClient(app)

        resp = client.get("/api/v1/apikeys/me")
        assert resp.status_code == 401
        assert "missing" in resp.json()["detail"].lower()

    def test_invalid_api_key_returns_401(self) -> None:
        app, _token_service, _user_repo, _key_repo, _key_hasher = _build_app()
        client = TestClient(app)

        resp = client.get(
            "/api/v1/apikeys/me",
            headers={"X-API-Key": "ks_invalid_secret"},
        )
        assert resp.status_code == 401
