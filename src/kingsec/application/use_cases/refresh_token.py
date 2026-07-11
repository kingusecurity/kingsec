"""Use case: refresh an access token using a refresh token.

Steps:
    1. Verify the refresh token (check expiry, signature, type).
    2. Look up the user to ensure they still exist and are active.
    3. Generate a new access token.
    4. Optionally rotate the refresh token (security best practice).

Security considerations:
    - Refresh tokens are verified for type == "refresh" to prevent access
      token reuse.
    - User existence is checked to handle deleted/disabled accounts.
    - The old refresh token is not revoked (stateless refresh) for simplicity;
      add revocation for higher security requirements.
"""

from __future__ import annotations

from ..dto import RefreshTokenRequest, RefreshTokenResponse
from ..ports import PasswordHasher, TokenService, UserRepository
from ..errors import ApplicationError


class RefreshToken:
    """Issue a new access token using a valid refresh token."""

    def __init__(
        self,
        users: UserRepository,
        tokens: TokenService,
    ) -> None:
        self._users = users
        self._tokens = tokens

    def execute(self, request: RefreshTokenRequest) -> RefreshTokenResponse:
        # Step 1: Verify the refresh token.
        try:
            claims = self._tokens.verify_refresh_token(request.refresh_token)
        except Exception as exc:
            raise TokenRefreshError("invalid or expired refresh token") from exc

        # Step 2: Verify the token type (prevent access token reuse).
        if claims.token_type != "refresh":
            raise TokenRefreshError("invalid token type")

        # Step 3: Look up the user to ensure they still exist and are active.
        user = self._users.find_by_id(claims.user_id)
        if user is None:
            raise TokenRefreshError("user not found")
        if not user.is_active:
            raise TokenRefreshError("account is disabled")

        # Step 4: Generate a new access token.
        access_token = self._tokens.create_access_token(
            user_id=user.id,
            username=user.username,
            role=user.role.label,
        )

        return RefreshTokenResponse(access_token=access_token)


class TokenRefreshError(ApplicationError):
    """Raised when token refresh fails."""
