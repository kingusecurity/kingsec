"""Integration test: unified JWT/API-key resolution in get_current_user().

Verifies the fix for the gap the API-key audit found: an API key can now
authenticate on generic business routes (via Authorization: Bearer or
X-API-Key), not just /apikeys/me. Also verifies the safety properties that
make broadening this safe: the key's owner must still be active, a
read_only key is restricted to safe HTTP methods, and get_current_user_jwt_only
never accepts an API key regardless of scope.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.auth import (
    CurrentUser,
    get_current_user,
    get_current_user_jwt_only,
)
from kingsec.application import ValidateApiKey
from kingsec.application.ports import ApiKeyHasher, ApiKeyRepository, TokenService, UserRepository
from kingsec.domain import Role, User
from kingsec.infrastructure.config import Settings

from .test_api_key_integration import StubApiKeyHasher, StubApiKeyRepository
from .test_auth_integration import StubTokenService, StubUserRepo


def _build_app() -> tuple[FastAPI, StubTokenService, StubUserRepo, StubApiKeyRepository, StubApiKeyHasher]:
    token_service = StubTokenService()
    user_repo = StubUserRepo()
    key_repo = StubApiKeyRepository()
    key_hasher = StubApiKeyHasher()

    app = FastAPI()

    class _StubApp:
        settings = Settings()

        def resolve(self, service_type: type):
            if service_type == TokenService:
                return token_service
            if service_type == UserRepository:
                return user_repo
            if service_type == ApiKeyRepository:
                return key_repo
            if service_type == ApiKeyHasher:
                return key_hasher
            if service_type == ValidateApiKey:
                return ValidateApiKey(key_repo, key_hasher)
            raise ValueError(f"Unknown service: {service_type}")

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    def _identity(current_user: CurrentUser = Depends(get_current_user)) -> dict:
        return {
            "user_id": current_user.user_id,
            "role": current_user.role.label,
            "via_api_key": current_user.api_key is not None,
        }

    def _identity_jwt_only(current_user: CurrentUser = Depends(get_current_user_jwt_only)) -> dict:
        return {"user_id": current_user.user_id, "via_api_key": current_user.api_key is not None}

    # A generic read route and a generic mutating route, standing in for
    # "any business route protected by get_current_user" - exactly the
    # gap the audit found (the key mechanism worked in isolation but
    # never reached anything except /apikeys/me).
    app.get("/_test/protected")(_identity)
    app.post("/_test/protected")(_identity)
    app.get("/_test/jwt-only")(_identity_jwt_only)

    return app, token_service, user_repo, key_repo, key_hasher


def _make_user(user_id: str = "user-1", username: str = "alice", role: Role = Role.ANALYST) -> User:
    return User(
        id=user_id,
        username=username,
        email=f"{username}@example.com",
        password_hash="hashed:irrelevant",
        role=role,
    )


class TestUnifiedAuthResolution:
    """Case A/B from the design's walkthrough: a key now works on generic routes."""

    def test_jwt_bearer_still_works_unchanged(self) -> None:
        app, tokens, user_repo, _key_repo, _key_hasher = _build_app()
        user = _make_user()
        user_repo.save(user)
        token = tokens.create_access_token(user.id, user.username, user.role.label)
        client = TestClient(app)

        resp = client.get("/_test/protected", headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        assert resp.json() == {"user_id": user.id, "role": user.role.label, "via_api_key": False}

    def test_full_access_key_via_authorization_bearer_works_on_business_route(self) -> None:
        """Case A: key sent as `Authorization: Bearer` against a real business route."""
        from kingsec.domain.api_key import ApiKey, ApiKeyScope

        app, _tokens, user_repo, key_repo, key_hasher = _build_app()
        owner = _make_user()
        user_repo.save(owner)
        plaintext = "ks_key-1_secret"
        key_repo.save(
            ApiKey(id="key-1", user_id=owner.id, name="CI", key_hash=key_hasher.hash(plaintext), scope=ApiKeyScope.FULL_ACCESS)
        )
        client = TestClient(app)

        resp = client.get("/_test/protected", headers={"Authorization": f"Bearer {plaintext}"})

        assert resp.status_code == 200
        body = resp.json()
        assert body["user_id"] == owner.id
        assert body["via_api_key"] is True

    def test_key_via_x_api_key_header_works_on_a_different_business_route(self) -> None:
        """Case B: a different key sent via `X-API-Key` against a different business route."""
        from kingsec.domain.api_key import ApiKey, ApiKeyScope

        app, _tokens, user_repo, key_repo, key_hasher = _build_app()
        owner = _make_user()
        user_repo.save(owner)
        plaintext = "ks_key-2_secret"
        key_repo.save(
            ApiKey(id="key-2", user_id=owner.id, name="Automation", key_hash=key_hasher.hash(plaintext), scope=ApiKeyScope.FULL_ACCESS)
        )
        client = TestClient(app)

        resp = client.post("/_test/protected", headers={"X-API-Key": plaintext})

        assert resp.status_code == 200
        assert resp.json()["via_api_key"] is True

    def test_no_credentials_returns_401(self) -> None:
        app, *_ = _build_app()
        client = TestClient(app)

        resp = client.get("/_test/protected")

        assert resp.status_code == 401

    def test_malformed_ks_prefixed_bearer_is_rejected_as_a_key_not_reinterpreted_as_jwt(self) -> None:
        app, *_ = _build_app()
        client = TestClient(app)

        resp = client.get("/_test/protected", headers={"Authorization": "Bearer ks_not_a_real_key"})

        assert resp.status_code == 401


class TestOwnerActiveCheck:
    def test_deactivated_owners_key_stops_working(self) -> None:
        from kingsec.domain.api_key import ApiKey, ApiKeyScope

        app, _tokens, user_repo, key_repo, key_hasher = _build_app()
        owner = _make_user()
        user_repo.save(owner)
        plaintext = "ks_key-3_secret"
        key_repo.save(
            ApiKey(id="key-3", user_id=owner.id, name="Key", key_hash=key_hasher.hash(plaintext), scope=ApiKeyScope.FULL_ACCESS)
        )
        client = TestClient(app)

        # Works while the owner is active.
        ok_resp = client.get("/_test/protected", headers={"X-API-Key": plaintext})
        assert ok_resp.status_code == 200

        # Deactivate the owner - the key itself is untouched (still active,
        # unrevoked) but must stop working anyway.
        owner.disable()
        user_repo.save(owner)

        blocked_resp = client.get("/_test/protected", headers={"X-API-Key": plaintext})
        assert blocked_resp.status_code == 401

    def test_key_for_nonexistent_owner_is_rejected(self) -> None:
        from kingsec.domain.api_key import ApiKey, ApiKeyScope

        app, _tokens, _user_repo, key_repo, key_hasher = _build_app()
        plaintext = "ks_key-4_secret"
        key_repo.save(
            ApiKey(id="key-4", user_id="ghost-user", name="Orphan", key_hash=key_hasher.hash(plaintext), scope=ApiKeyScope.FULL_ACCESS)
        )
        client = TestClient(app)

        resp = client.get("/_test/protected", headers={"X-API-Key": plaintext})

        assert resp.status_code == 401


class TestScopeEnforcement:
    def test_read_only_key_succeeds_on_get(self) -> None:
        from kingsec.domain.api_key import ApiKey, ApiKeyScope

        app, _tokens, user_repo, key_repo, key_hasher = _build_app()
        owner = _make_user()
        user_repo.save(owner)
        plaintext = "ks_key-5_secret"
        key_repo.save(
            ApiKey(id="key-5", user_id=owner.id, name="RO", key_hash=key_hasher.hash(plaintext), scope=ApiKeyScope.READ_ONLY)
        )
        client = TestClient(app)

        resp = client.get("/_test/protected", headers={"X-API-Key": plaintext})

        assert resp.status_code == 200

    def test_read_only_key_gets_403_on_mutating_route(self) -> None:
        from kingsec.domain.api_key import ApiKey, ApiKeyScope

        app, _tokens, user_repo, key_repo, key_hasher = _build_app()
        owner = _make_user()
        user_repo.save(owner)
        plaintext = "ks_key-6_secret"
        key_repo.save(
            ApiKey(id="key-6", user_id=owner.id, name="RO", key_hash=key_hasher.hash(plaintext), scope=ApiKeyScope.READ_ONLY)
        )
        client = TestClient(app)

        resp = client.post("/_test/protected", headers={"X-API-Key": plaintext})

        assert resp.status_code == 403

    def test_full_access_key_succeeds_on_get_and_post(self) -> None:
        from kingsec.domain.api_key import ApiKey, ApiKeyScope

        app, _tokens, user_repo, key_repo, key_hasher = _build_app()
        owner = _make_user()
        user_repo.save(owner)
        plaintext = "ks_key-7_secret"
        key_repo.save(
            ApiKey(id="key-7", user_id=owner.id, name="FA", key_hash=key_hasher.hash(plaintext), scope=ApiKeyScope.FULL_ACCESS)
        )
        client = TestClient(app)

        get_resp = client.get("/_test/protected", headers={"X-API-Key": plaintext})
        post_resp = client.post("/_test/protected", headers={"X-API-Key": plaintext})

        assert get_resp.status_code == 200
        assert post_resp.status_code == 200


class TestJwtOnlyDependency:
    """get_current_user_jwt_only must never accept an API key, of either scope."""

    def test_jwt_still_works(self) -> None:
        app, tokens, user_repo, _key_repo, _key_hasher = _build_app()
        user = _make_user()
        user_repo.save(user)
        token = tokens.create_access_token(user.id, user.username, user.role.label)
        client = TestClient(app)

        resp = client.get("/_test/jwt-only", headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        assert resp.json()["via_api_key"] is False

    def test_full_access_api_key_is_rejected(self) -> None:
        from kingsec.domain.api_key import ApiKey, ApiKeyScope

        app, _tokens, user_repo, key_repo, key_hasher = _build_app()
        owner = _make_user()
        user_repo.save(owner)
        plaintext = "ks_key-8_secret"
        key_repo.save(
            ApiKey(id="key-8", user_id=owner.id, name="FA", key_hash=key_hasher.hash(plaintext), scope=ApiKeyScope.FULL_ACCESS)
        )
        client = TestClient(app)

        resp = client.get("/_test/jwt-only", headers={"X-API-Key": plaintext})

        assert resp.status_code == 401

    def test_no_credentials_returns_401(self) -> None:
        app, *_ = _build_app()
        client = TestClient(app)

        resp = client.get("/_test/jwt-only")

        assert resp.status_code == 401
