"""Authentication-related DTOs for the application layer.

Design decisions:
    - Request DTOs are plain dataclasses (not Pydantic) to keep the
      application layer framework-free.
    - Response DTOs include only the information the caller needs.
    - Sensitive data (passwords, tokens) are never stored in DTOs after use.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LoginRequest:
    """Request to authenticate a user."""

    username: str
    password: str


@dataclass(frozen=True)
class LoginResponse:
    """Response from successful authentication."""

    user_id: str
    username: str
    role: str
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 1800  # 30 minutes in seconds


@dataclass(frozen=True)
class RefreshTokenRequest:
    """Request to refresh an access token."""

    refresh_token: str


@dataclass(frozen=True)
class RefreshTokenResponse:
    """Response from successful token refresh."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = 1800  # 30 minutes in seconds


@dataclass(frozen=True)
class RegisterUserRequest:
    """Request to register a new user."""

    username: str
    email: str
    password: str
    role: str = "viewer"  # default to least-privileged


@dataclass(frozen=True)
class RegisterUserResponse:
    """Response from successful user registration."""

    user_id: str
    username: str
    email: str
    role: str


@dataclass(frozen=True)
class UserView:
    """User information view (no sensitive data)."""

    user_id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: str
    last_login_at: str | None


@dataclass(frozen=True)
class ChangePasswordRequest:
    """Request to change a user's password."""

    user_id: str
    current_password: str
    new_password: str


@dataclass(frozen=True)
class AdminChangePasswordRequest:
    """Request for admin to change a user's password."""

    user_id: str
    new_password: str