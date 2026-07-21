"""JWT token service — infrastructure implementation.

Uses PyJWT for token creation and verification. Tokens are signed with
HMAC-SHA256 (HS256) using a secret key from configuration.

Security considerations:
    - Secret key is loaded from configuration (env var / .env).
    - Access tokens: short-lived (30 min default).
    - Refresh tokens: long-lived (7 days default).
    - Token revocation uses an in-memory set (swap to Redis for production).
    - All token operations are thread-safe.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

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

    def __init__(self, settings: JWTSettings) -> None:
        self._secret = settings.secret_key.get_secret_value()
        self._algorithm = settings.algorithm
        self._access_expire = timedelta(minutes=settings.access_token_expire_minutes)
        self._refresh_expire = timedelta(days=settings.refresh_token_expire_days)
        self._issuer = settings.issuer
        self._revoked: set[str] = set()

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

    def _verify(self, token: str, expected_type: str) -> TokenClaims:
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
        self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked


def _to_datetime(value: int | float) -> datetime:
    """Convert a UNIX timestamp to a timezone-aware datetime."""
    return datetime.fromtimestamp(value, tz=UTC)
