"""Port for JWT token operations — application layer contract.

The ``TokenService`` port defines how the application creates and verifies
JWT tokens. Infrastructure implements this port with PyJWT; the application
never imports JWT libraries.

Design decisions:
    - create_access_token: generates a short-lived access token (default 30 min).
    - create_refresh_token: generates a long-lived refresh token (default 7 days).
    - verify_access_token: validates and decodes an access token, returning claims.
    - verify_refresh_token: validates and decodes a refresh token, returning claims.
    - Token payloads include: sub (user_id), role, exp, iat, jti (unique id), type.
    - The port is technology-agnostic; the infrastructure decides the JWT library.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class TokenClaims:
    """Decoded JWT token claims."""

    user_id: str
    username: str
    role: str
    token_type: str  # "access", "refresh", or "mfa_pending"
    jti: str  # unique token identifier
    issued_at: datetime
    expires_at: datetime


class TokenError(Exception):
    """Base error for token operations."""


class TokenExpiredError(TokenError):
    """Raised when a token has expired."""


class TokenInvalidError(TokenError):
    """Raised when a token is malformed or has invalid claims."""


class TokenService(ABC):
    """Abstract port for JWT token operations."""

    @abstractmethod
    def create_access_token(
        self,
        user_id: str,
        username: str,
        role: str,
    ) -> str:
        """Create a short-lived access token.

        Args:
            user_id: The subject (user ID).
            username: The username for claims.
            role: The user's role string.

        Returns:
            The encoded JWT string.
        """

    @abstractmethod
    def create_refresh_token(
        self,
        user_id: str,
        username: str,
        role: str,
    ) -> str:
        """Create a long-lived refresh token.

        Args:
            user_id: The subject (user ID).
            username: The username for claims.
            role: The user's role string.

        Returns:
            The encoded JWT string.
        """

    @abstractmethod
    def create_mfa_pending_token(
        self,
        user_id: str,
        username: str,
        role: str,
    ) -> str:
        """Create a short-lived token proving password+lockout+active-account
        checks passed, pending a second factor.

        This token has no capability beyond completing the in-progress login:
        it is a distinct ``type`` claim, so it is rejected by
        ``verify_access_token``/``verify_refresh_token`` on every other
        protected route, by the exact same type-mismatch check that already
        governs access vs. refresh tokens - no new authorization logic to
        get wrong.

        Args:
            user_id: The subject (user ID).
            username: The username for claims.
            role: The user's role string.

        Returns:
            The encoded JWT string.
        """

    @abstractmethod
    def verify_access_token(self, token: str) -> TokenClaims:
        """Verify and decode an access token.

        Args:
            token: The JWT string to verify.

        Returns:
            The decoded token claims.

        Raises:
            TokenExpiredError: If the token has expired.
            TokenInvalidError: If the token is malformed or has invalid claims.
        """

    @abstractmethod
    def verify_refresh_token(self, token: str) -> TokenClaims:
        """Verify and decode a refresh token.

        Args:
            token: The JWT string to verify.

        Returns:
            The decoded token claims.

        Raises:
            TokenExpiredError: If the token has expired.
            TokenInvalidError: If the token is malformed or has invalid claims.
        """

    @abstractmethod
    def verify_mfa_pending_token(self, token: str) -> TokenClaims:
        """Verify and decode a pending-MFA token.

        Args:
            token: The JWT string to verify.

        Returns:
            The decoded token claims.

        Raises:
            TokenExpiredError: If the token has expired.
            TokenInvalidError: If the token is malformed, has invalid claims,
                or has already been used (revoked).
        """

    @abstractmethod
    def revoke_token(self, jti: str) -> None:
        """Revoke a token by its unique ID (blacklist).

        Args:
            jti: The unique token identifier to revoke.
        """

    @abstractmethod
    def is_revoked(self, jti: str) -> bool:
        """Check if a token has been revoked.

        Args:
            jti: The unique token identifier to check.

        Returns:
            True if the token has been revoked.
        """
