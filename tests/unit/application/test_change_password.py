"""Tests for ChangePassword use case."""

from __future__ import annotations

import pytest

from kingsec.application.dto import ChangePasswordRequest
from kingsec.application.ports import PasswordHasher, UserRepository
from kingsec.application.use_cases.change_password import ChangePassword, PasswordChangeError
from kingsec.domain import Role, User
from kingsec.domain.user import PasswordValidationError

# --- Stubs --------------------------------------------------------------------


class StubPasswordHasher(PasswordHasher):
    def __init__(self, verify_result: bool = True) -> None:
        self._verify_result = verify_result
        self.hashed_passwords: list[str] = []

    def hash(self, password: str) -> str:
        self.hashed_passwords.append(password)
        return f"hashed:{password}"

    def verify(self, password: str, password_hash: str) -> bool:
        return self._verify_result


class StubUserRepository(UserRepository):
    def __init__(self, user: User | None = None) -> None:
        self._user = user
        self.saved_users: list[User] = []

    def find_by_username(self, username: str) -> User | None:
        return None

    def find_by_id(self, user_id: str) -> User | None:
        return self._user

    def save(self, user: User) -> None:
        self.saved_users.append(user)

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
        password_hash="hashed:oldpassword",
        role=Role.VIEWER,
    )
    defaults.update(kwargs)
    return User(**defaults)


# --- Tests --------------------------------------------------------------------


class TestChangePassword:
    def test_successful_password_change(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher(verify_result=True)

        change = ChangePassword(repo, hasher)
        request = ChangePasswordRequest(
            user_id="user-001",
            current_password="oldpassword",
            new_password="NewSecurePass1",
        )
        change.execute(request)

        assert len(repo.saved_users) == 1
        assert len(hasher.hashed_passwords) == 1
        assert hasher.hashed_passwords[0] == "NewSecurePass1"

    def test_change_with_wrong_current_password(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher(verify_result=False)

        change = ChangePassword(repo, hasher)
        request = ChangePasswordRequest(
            user_id="user-001",
            current_password="wrongpassword",
            new_password="NewSecurePass1",
        )

        with pytest.raises(PasswordChangeError, match="incorrect"):
            change.execute(request)

    def test_change_with_nonexistent_user(self) -> None:
        repo = StubUserRepository(user=None)
        hasher = StubPasswordHasher()

        change = ChangePassword(repo, hasher)
        request = ChangePasswordRequest(
            user_id="nonexistent",
            current_password="old",
            new_password="NewSecurePass1",
        )

        with pytest.raises(PasswordChangeError, match="not found"):
            change.execute(request)

    def test_change_with_weak_new_password(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher(verify_result=True)

        change = ChangePassword(repo, hasher)
        request = ChangePasswordRequest(
            user_id="user-001",
            current_password="oldpassword",
            new_password="short",
        )

        with pytest.raises(PasswordValidationError):
            change.execute(request)
