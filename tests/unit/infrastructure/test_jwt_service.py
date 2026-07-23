"""Tests for JWT token service infrastructure."""

from __future__ import annotations

import pytest

from kingsec.application.ports import TokenInvalidError
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

    def test_cleanup_expired_removes_expired_rows(self, tmp_path: pytest.TempPathFactory) -> None:
        from sqlalchemy import create_engine

        from kingsec.infrastructure.persistence.base import Base
        from kingsec.infrastructure.persistence.models import RevokedTokenORM

        db_path = tmp_path / "test_cleanup.db"
        engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(engine)

        from sqlalchemy.orm import sessionmaker
        sf = sessionmaker(bind=engine)

        svc = JWTTokenService(
            JWTSettings(secret_key="test-secret-key"),
            session_factory=sf,
        )

        svc.revoke_token("expired-jti")
        svc.revoke_token("active-jti")

        with sf() as session:
            row = session.get(RevokedTokenORM, "expired-jti")
            row.expires_at = "2000-01-01T00:00:00+00:00"
            session.commit()

        assert svc.is_revoked("expired-jti") is True
        assert svc.is_revoked("active-jti") is True

        count = svc.cleanup_expired()
        assert count == 1

        assert svc.is_revoked("expired-jti") is False
        assert svc.is_revoked("active-jti") is True
        with sf() as session:
            assert session.get(RevokedTokenORM, "expired-jti") is None
            assert session.get(RevokedTokenORM, "active-jti") is not None

    def test_cleanup_does_not_remove_active_revocations(self, tmp_path: pytest.TempPathFactory) -> None:
        from sqlalchemy import create_engine

        from kingsec.infrastructure.persistence.base import Base
        from kingsec.infrastructure.persistence.models import RevokedTokenORM

        db_path = tmp_path / "test_active.db"
        engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(engine)

        from sqlalchemy.orm import sessionmaker
        sf = sessionmaker(bind=engine)

        svc = JWTTokenService(
            JWTSettings(secret_key="test-secret-key"),
            session_factory=sf,
        )

        svc.revoke_token("still-active-jti")

        count = svc.cleanup_expired()
        assert count == 0

        assert svc.is_revoked("still-active-jti") is True
        with sf() as session:
            assert session.get(RevokedTokenORM, "still-active-jti") is not None
