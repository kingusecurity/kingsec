"""Tests for JWT token service infrastructure."""

from __future__ import annotations

import pytest
from datetime import timedelta

from kingsec.application.ports import TokenExpiredError, TokenInvalidError
from kingsec.infrastructure.auth.jwt_service import JWTTokenService
from kingsec.infrastructure.config.models import JWTSettings


@pytest.fixture
def jwt_settings() -> JWTSettings:
    return JWTSettings(
        secret_key="test-secret-key-for-testing-only",
        algorithm="HS256",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
        issuer="kingsec-test",
    )


@pytest.fixture
def token_service(jwt_settings: JWTSettings) -> JWTTokenService:
    return JWTTokenService(jwt_settings)


class TestJWTTokenService:
    def test_create_access_token_returns_string(self, token_service: JWTTokenService) -> None:
        token = token_service.create_access_token(
            user_id="user-001",
            username="testuser",
            role="Viewer",
        )
        assert isinstance(token, str)
        assert len(token) > 0

    def test_create_refresh_token_returns_string(self, token_service: JWTTokenService) -> None:
        token = token_service.create_refresh_token(
            user_id="user-001",
            username="testuser",
            role="Viewer",
        )
        assert isinstance(token, str)
        assert len(token) > 0

    def test_verify_access_token_success(self, token_service: JWTTokenService) -> None:
        token = token_service.create_access_token(
            user_id="user-001",
            username="testuser",
            role="Admin",
        )
        claims = token_service.verify_access_token(token)
        assert claims.user_id == "user-001"
        assert claims.username == "testuser"
        assert claims.role == "Admin"
        assert claims.token_type == "access"

    def test_verify_refresh_token_success(self, token_service: JWTTokenService) -> None:
        token = token_service.create_refresh_token(
            user_id="user-001",
            username="testuser",
            role="Analyst",
        )
        claims = token_service.verify_refresh_token(token)
        assert claims.user_id == "user-001"
        assert claims.username == "testuser"
        assert claims.role == "Analyst"
        assert claims.token_type == "refresh"

    def test_access_token_rejected_as_refresh(self, token_service: JWTTokenService) -> None:
        token = token_service.create_access_token(
            user_id="user-001",
            username="testuser",
            role="Viewer",
        )
        with pytest.raises(TokenInvalidError, match="expected refresh token"):
            token_service.verify_refresh_token(token)

    def test_refresh_token_rejected_as_access(self, token_service: JWTTokenService) -> None:
        token = token_service.create_refresh_token(
            user_id="user-001",
            username="testuser",
            role="Viewer",
        )
        with pytest.raises(TokenInvalidError, match="expected access token"):
            token_service.verify_access_token(token)

    def test_invalid_token_rejected(self, token_service: JWTTokenService) -> None:
        with pytest.raises(TokenInvalidError):
            token_service.verify_access_token("not.a.valid.token")

    def test_wrong_secret_rejected(self, jwt_settings: JWTSettings) -> None:
        service1 = JWTTokenService(jwt_settings)
        token = service1.create_access_token("user-001", "test", "Viewer")

        # Different secret
        settings2 = JWTSettings(secret_key="different-secret-key")
        service2 = JWTTokenService(settings2)
        with pytest.raises(TokenInvalidError):
            service2.verify_access_token(token)

    def test_token_revocation(self, token_service: JWTTokenService) -> None:
        token = token_service.create_access_token(
            user_id="user-001",
            username="testuser",
            role="Viewer",
        )
        claims = token_service.verify_access_token(token)
        assert token_service.is_revoked(claims.jti) is False

        token_service.revoke_token(claims.jti)
        assert token_service.is_revoked(claims.jti) is True

        with pytest.raises(TokenInvalidError, match="revoked"):
            token_service.verify_access_token(token)

    def test_token_has_jti(self, token_service: JWTTokenService) -> None:
        token = token_service.create_access_token(
            user_id="user-001",
            username="testuser",
            role="Viewer",
        )
        claims = token_service.verify_access_token(token)
        assert len(claims.jti) > 0

    def test_token_has_issued_at(self, token_service: JWTTokenService) -> None:
        token = token_service.create_access_token(
            user_id="user-001",
            username="testuser",
            role="Viewer",
        )
        claims = token_service.verify_access_token(token)
        assert claims.issued_at is not None
        assert claims.expires_at is not None
        assert claims.expires_at > claims.issued_at
