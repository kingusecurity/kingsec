"""Tests for Login use case."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kingsec.application.dto import LoginRequest
from kingsec.application.ports import PasswordHasher, TokenClaims, TokenService, UserRepository
from kingsec.application.use_cases.login import AuthenticationError, Login
from kingsec.domain import Role, User

# --- Stubs --------------------------------------------------------------------


class StubPasswordHasher(PasswordHasher):
    def __init__(self, verify_result: bool = True) -> None:
        self._verify_result = verify_result
        self.hash_called = False
        self.verify_called = False

    def hash(self, password: str) -> str:
        self.hash_called = True
        return f"hashed:{password}"

    def verify(self, password: str, password_hash: str) -> bool:
        self.verify_called = True
        return self._verify_result


class StubTokenService(TokenService):
    def __init__(self) -> None:
        self.create_access_called = False
        self.create_refresh_called = False

    def create_access_token(self, user_id: str, username: str, role: str) -> str:
        self.create_access_called = True
        return f"access-token-{user_id}"

    def create_refresh_token(self, user_id: str, username: str, role: str) -> str:
        self.create_refresh_called = True
        return f"refresh-token-{user_id}"

    def verify_access_token(self, token: str) -> TokenClaims:
        return TokenClaims(
            user_id="user-001",
            username="test",
            role="Viewer",
            token_type="access",
            jti="jti-1",
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC),
        )

    def verify_refresh_token(self, token: str) -> TokenClaims:
        return self.verify_access_token(token)

    def revoke_token(self, jti: str) -> None:
        pass

    def is_revoked(self, jti: str) -> bool:
        return False


class StubUserRepository(UserRepository):
    def __init__(self, user: User | None = None) -> None:
        self._user = user
        self.save_called = False

    def find_by_username(self, username: str) -> User | None:
        return self._user

    def find_by_id(self, user_id: str) -> User | None:
        return self._user

    def save(self, user: User) -> None:
        self.save_called = True

    def exists_by_username(self, username: str) -> bool:
        return self._user is not None and self._user.username == username

    def exists_by_email(self, email: str) -> bool:
        return self._user is not None and self._user.email == email

    def list_all(self, limit: int = 50, offset: int = 0) -> list[User]:
        return [self._user] if self._user else []

    def count(self) -> int:
        return 1 if self._user else 0

    def count_by_role(self, role: Role) -> int:
        return 1 if self._user and role == Role.ADMIN else 0

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


class TestLogin:
    def test_successful_login(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher(verify_result=True)
        tokens = StubTokenService()

        login = Login(repo, hasher, tokens)
        request = LoginRequest(username="testuser", password="password")
        result = login.execute(request)

        assert result.user_id == "user-001"
        assert result.username == "testuser"
        assert result.access_token == "access-token-user-001"
        assert result.refresh_token == "refresh-token-user-001"
        assert tokens.create_access_called is True
        assert tokens.create_refresh_called is True
        assert repo.save_called is True

    def test_login_records_last_login(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher(verify_result=True)
        tokens = StubTokenService()

        login = Login(repo, hasher, tokens)
        request = LoginRequest(username="testuser", password="password")
        login.execute(request)

        assert repo.save_called is True

    def test_login_with_wrong_password(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher(verify_result=False)
        tokens = StubTokenService()

        login = Login(repo, hasher, tokens)
        request = LoginRequest(username="testuser", password="wrong")

        with pytest.raises(AuthenticationError, match="invalid username or password"):
            login.execute(request)

    def test_login_with_nonexistent_user(self) -> None:
        repo = StubUserRepository(user=None)
        hasher = StubPasswordHasher()
        tokens = StubTokenService()

        login = Login(repo, hasher, tokens)
        request = LoginRequest(username="nobody", password="password")

        with pytest.raises(AuthenticationError, match="invalid username or password"):
            login.execute(request)

    def test_login_with_disabled_account(self) -> None:
        user = _make_user(is_active=False)
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher(verify_result=True)
        tokens = StubTokenService()

        login = Login(repo, hasher, tokens)
        request = LoginRequest(username="testuser", password="password")

        with pytest.raises(AuthenticationError, match="disabled"):
            login.execute(request)
