"""Tests for RefreshToken use case."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kingsec.application.dto import RefreshTokenRequest
from kingsec.application.ports import TokenClaims, TokenService, UserRepository
from kingsec.application.use_cases.refresh_token import RefreshToken, TokenRefreshError
from kingsec.domain import Role, User

# --- Stubs --------------------------------------------------------------------


class StubTokenService(TokenService):
    def __init__(
        self,
        valid: bool = True,
        token_type: str = "refresh",
        user_id: str = "user-001",
    ) -> None:
        self._valid = valid
        self._token_type = token_type
        self._user_id = user_id

    def create_access_token(self, user_id: str, username: str, role: str) -> str:
        return f"new-access-{user_id}"

    def create_refresh_token(self, user_id: str, username: str, role: str) -> str:
        return f"new-refresh-{user_id}"

    def create_mfa_pending_token(self, user_id: str, username: str, role: str) -> str:
        return f"pending-{user_id}"

    def verify_access_token(self, token: str) -> TokenClaims:
        return self._make_claims("access")

    def verify_refresh_token(self, token: str) -> TokenClaims:
        if not self._valid:
            raise Exception("invalid token")
        return self._make_claims(self._token_type)

    def verify_mfa_pending_token(self, token: str) -> TokenClaims:
        return self._make_claims("mfa_pending")

    def _make_claims(self, token_type: str) -> TokenClaims:
        return TokenClaims(
            user_id=self._user_id,
            username="testuser",
            role="Viewer",
            token_type=token_type,
            jti="jti-1",
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC),
        )

    def revoke_token(self, jti: str) -> None:
        pass

    def is_revoked(self, jti: str) -> bool:
        return False


class StubUserRepository(UserRepository):
    def __init__(self, user: User | None = None) -> None:
        self._user = user

    def find_by_username(self, username: str) -> User | None:
        return self._user

    def find_by_id(self, user_id: str) -> User | None:
        return self._user

    def save(self, user: User) -> None:
        pass

    def exists_by_username(self, username: str) -> bool:
        return False

    def exists_by_email(self, email: str) -> bool:
        return False

    def list_all(self, limit: int = 50, offset: int = 0) -> list[User]:
        return []

    def count(self) -> int:
        return 0

    def count_by_role(self, role: Role) -> int:
        return 0

    def search(
        self,
        *,
        query: str | None = None,
        role: str | None = None,
        is_active: bool | None = None,
        limit: int = 50,
        offset: int = 0,
        order_by: str = "username",
        order_dir: str = "asc",
    ) -> tuple[list[User], int]:
        return ([], 0)


def _make_user(**kwargs) -> User:
    defaults = dict(
        id="user-001",
        username="testuser",
        email="test@example.com",
        password_hash="hashed:password",
        role=Role.VIEWER,
    )
    defaults.update(kwargs)
    return User(**defaults)


# --- Tests --------------------------------------------------------------------


class TestRefreshToken:
    def test_successful_refresh(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        tokens = StubTokenService(valid=True)

        refresh = RefreshToken(repo, tokens)
        request = RefreshTokenRequest(refresh_token="valid.refresh.token")
        result = refresh.execute(request)

        assert result.access_token == "new-access-user-001"

    def test_refresh_with_invalid_token(self) -> None:
        repo = StubUserRepository(_make_user())
        tokens = StubTokenService(valid=False)

        refresh = RefreshToken(repo, tokens)
        request = RefreshTokenRequest(refresh_token="invalid.token")

        with pytest.raises(TokenRefreshError, match="invalid or expired"):
            refresh.execute(request)

    def test_refresh_with_wrong_token_type(self) -> None:
        repo = StubUserRepository(_make_user())
        tokens = StubTokenService(valid=True, token_type="access")

        refresh = RefreshToken(repo, tokens)
        request = RefreshTokenRequest(refresh_token="access.token")

        with pytest.raises(TokenRefreshError, match="invalid token type"):
            refresh.execute(request)

    def test_refresh_with_nonexistent_user(self) -> None:
        repo = StubUserRepository(user=None)
        tokens = StubTokenService(valid=True)

        refresh = RefreshToken(repo, tokens)
        request = RefreshTokenRequest(refresh_token="valid.token")

        with pytest.raises(TokenRefreshError, match="user not found"):
            refresh.execute(request)

    def test_refresh_with_disabled_user(self) -> None:
        repo = StubUserRepository(_make_user(is_active=False))
        tokens = StubTokenService(valid=True)

        refresh = RefreshToken(repo, tokens)
        request = RefreshTokenRequest(refresh_token="valid.token")

        with pytest.raises(TokenRefreshError, match="disabled"):
            refresh.execute(request)
