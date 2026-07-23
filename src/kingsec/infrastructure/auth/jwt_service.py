"""JWT token service — infrastructure implementation.

Uses PyJWT for token creation and verification. Tokens are signed with
HMAC-SHA256 (HS256) using a secret key from configuration.

Security considerations:
    - Secret key is loaded from configuration (env var / .env).
    - Access tokens: short-lived (30 min default).
    - Refresh tokens: long-lived (7 days default).
    - Token revocation uses a database-backed store (survives restarts).
    - Expired revoked tokens are cleaned up lazily during verification.
    - All token operations are thread-safe.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Any

import jwt

from kingsec.application.ports import (
    TokenClaims,
    TokenExpiredError,
    TokenInvalidError,
    TokenService,
)
from kingsec.infrastructure.config.models import JWTSettings


class JWTTokenService(TokenService):
    """JWT token creation and verification using PyJWT."""

    def __init__(self, settings: JWTSettings, session_factory: Any = None) -> None:
        self._secret = settings.secret_key.get_secret_value()
        self._algorithm = settings.algorithm
        self._access_expire = timedelta(minutes=settings.access_token_expire_minutes)
        self._refresh_expire = timedelta(days=settings.refresh_token_expire_days)
        self._issuer = settings.issuer
        self._session_factory = session_factory
        self._revoked_fallback: set[str] = set()
        self._cleanup_counter = 0
        self._cleanup_lock = Lock()

    def create_access_token(
        self,
        user_id: str,
        username: str,
        role: str,
    ) -> str:
        now = datetime.now(UTC)
        payload = {
            "sub": user_id,
            "username": username,
            "role": role,
            "type": "access",
            "iat": now,
            "exp": now + self._access_expire,
            "iss": self._issuer,
            "jti": uuid.uuid4().hex,
        }
        return jwt.encode(payload, self._secret, algorithm=self._algorithm)

    def create_refresh_token(
        self,
        user_id: str,
        username: str,
        role: str,
    ) -> str:
        now = datetime.now(UTC)
        payload = {
            "sub": user_id,
            "username": username,
            "role": role,
            "type": "refresh",
            "iat": now,
            "exp": now + self._refresh_expire,
            "iss": self._issuer,
            "jti": uuid.uuid4().hex,
        }
        return jwt.encode(payload, self._secret, algorithm=self._algorithm)

    def verify_access_token(self, token: str) -> TokenClaims:
        return self._verify(token, expected_type="access")

    def verify_refresh_token(self, token: str) -> TokenClaims:
        return self._verify(token, expected_type="refresh")

    def cleanup_expired(self) -> int:
        """Remove expired revoked tokens from the database.

        Returns:
            Number of removed entries.
        """
        if self._session_factory is None:
            return 0
        from datetime import UTC, datetime

        from sqlalchemy import delete

        from kingsec.infrastructure.persistence.models import RevokedTokenORM

        now = datetime.now(UTC).isoformat()
        with self._session_factory() as session:
            result = session.execute(
                delete(RevokedTokenORM).where(RevokedTokenORM.expires_at < now)
            )
            session.commit()
            return int(result.rowcount) if result.rowcount is not None else 0

    def _verify(self, token: str, expected_type: str) -> TokenClaims:
        with self._cleanup_lock:
            self._cleanup_counter += 1
            if self._cleanup_counter >= 100 and self._session_factory is not None:
                self._cleanup_counter = 0
                self.cleanup_expired()
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                issuer=self._issuer,
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpiredError("token has expired") from exc
        except jwt.InvalidTokenError as exc:
            raise TokenInvalidError(f"invalid token: {exc}") from exc

        token_type = payload.get("type")
        if token_type != expected_type:
            raise TokenInvalidError(f"expected {expected_type} token, got {token_type}")

        jti = payload.get("jti", "")
        if self.is_revoked(jti):
            raise TokenInvalidError("token has been revoked")

        return TokenClaims(
            user_id=payload["sub"],
            username=payload.get("username", ""),
            role=payload.get("role", ""),
            token_type=token_type,
            jti=jti,
            issued_at=_to_datetime(payload.get("iat", 0)),
            expires_at=_to_datetime(payload.get("exp", 0)),
        )

    def revoke_token(self, jti: str) -> None:
        if self._session_factory is None:
            self._revoked_fallback.add(jti)
            return
        from datetime import UTC, datetime

        from kingsec.infrastructure.persistence.models import RevokedTokenORM

        now = datetime.now(UTC)
        expires_at = now + timedelta(days=7)
        with self._session_factory() as session:
            existing = session.get(RevokedTokenORM, jti)
            if existing is None:
                session.add(
                    RevokedTokenORM(
                        jti=jti,
                        revoked_at=now.isoformat(),
                        expires_at=expires_at.isoformat(),
                    )
                )
                session.commit()

    def is_revoked(self, jti: str) -> bool:
        if self._session_factory is None:
            return jti in self._revoked_fallback
        from kingsec.infrastructure.persistence.models import RevokedTokenORM

        with self._session_factory() as session:
            return session.get(RevokedTokenORM, jti) is not None


def _to_datetime(value: int | float) -> datetime:
    """Convert a UNIX timestamp to a timezone-aware datetime."""
    return datetime.fromtimestamp(value, tz=UTC)
