"""Use case: authenticate a user and issue tokens.

Steps:
    1. Look up the user by username.
    2. Verify the password against the stored hash.
    3. Check that the account is active.
    4. Generate access and refresh tokens.
    5. Record the login timestamp.

Security considerations:
    - Password verification uses constant-time comparison (via PasswordHasher).
    - Invalid credentials produce a generic error message (no username enumeration).
    - Disabled accounts are rejected with a specific error.
"""

from __future__ import annotations

from ..dto import LoginRequest, LoginResponse
from ..ports import PasswordHasher, TokenService, UserRepository
from ..errors import ApplicationError


class Login:
    """Authenticate a user and issue JWT tokens."""

    def __init__(
        self,
        users: UserRepository,
        hasher: PasswordHasher,
        tokens: TokenService,
    ) -> None:
        self._users = users
        self._hasher = hasher
        self._tokens = tokens

    def execute(self, request: LoginRequest) -> LoginResponse:
        # Step 1: Look up the user.
        user = self._users.find_by_username(request.username)
        if user is None:
            # Generic message to prevent username enumeration.
            raise AuthenticationError("invalid username or password")

        # Step 2: Verify the password.
        if not self._hasher.verify(request.password, user.password_hash):
            raise AuthenticationError("invalid username or password")

        # Step 3: Check that the account is active.
        if not user.is_active:
            raise AuthenticationError("account is disabled")

        # Step 4: Generate tokens.
        access_token = self._tokens.create_access_token(
            user_id=user.id,
            username=user.username,
            role=user.role.label,
        )
        refresh_token = self._tokens.create_refresh_token(
            user_id=user.id,
            username=user.username,
            role=user.role.label,
        )

        # Step 5: Record login.
        user.record_login()
        self._users.save(user)

        return LoginResponse(
            user_id=user.id,
            username=user.username,
            role=user.role.label,
            access_token=access_token,
            refresh_token=refresh_token,
        )


class AuthenticationError(ApplicationError):
    """Raised when authentication fails."""
