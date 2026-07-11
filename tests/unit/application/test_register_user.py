"""Tests for RegisterUser use case."""

from __future__ import annotations

import pytest

from kingsec.application.dto import RegisterUserRequest, RegisterUserResponse
from kingsec.application.ports import PasswordHasher, UserRepository
from kingsec.application.use_cases.register_user import RegisterUser, RegistrationError
from kingsec.domain import Role, User
from kingsec.domain.user import PasswordValidationError


# --- Stubs --------------------------------------------------------------------


class StubPasswordHasher(PasswordHasher):
    def hash(self, password: str) -> str:
        return f"hashed:{password}"

    def verify(self, password: str, password_hash: str) -> bool:
        return password_hash == f"hashed:{password}"


class StubUserRepository(UserRepository):
    def __init__(
        self,
        existing_username: str | None = None,
        existing_email: str | None = None,
    ) -> None:
        self._existing_username = existing_username
        self._existing_email = existing_email
        self.saved_users: list[User] = []

    def find_by_username(self, username: str) -> User | None:
        return None

    def find_by_id(self, user_id: str) -> User | None:
        return None

    def save(self, user: User) -> None:
        self.saved_users.append(user)

    def exists_by_username(self, username: str) -> bool:
        return self._existing_username is not None and username.lower() == self._existing_username.lower()

    def exists_by_email(self, email: str) -> bool:
        return self._existing_email is not None and email.lower() == self._existing_email.lower()

    def list_all(self, limit: int = 50, offset: int = 0) -> list[User]:
        return []

    def count(self) -> int:
        return 0


# --- Tests --------------------------------------------------------------------


class TestRegisterUser:
    def test_successful_registration(self) -> None:
        repo = StubUserRepository()
        hasher = StubPasswordHasher()

        register = RegisterUser(repo, hasher)
        request = RegisterUserRequest(
            username="newuser",
            email="new@example.com",
            password="SecurePass1",
            role="viewer",
        )
        result = register.execute(request)

        assert result.username == "newuser"
        assert result.email == "new@example.com"
        assert result.role == "Viewer"
        assert len(repo.saved_users) == 1

    def test_registration_with_duplicate_username(self) -> None:
        repo = StubUserRepository(existing_username="taken")
        hasher = StubPasswordHasher()

        register = RegisterUser(repo, hasher)
        request = RegisterUserRequest(
            username="taken",
            email="new@example.com",
            password="SecurePass1",
        )

        with pytest.raises(RegistrationError, match="username already taken"):
            register.execute(request)

    def test_registration_with_duplicate_email(self) -> None:
        repo = StubUserRepository(existing_email="taken@example.com")
        hasher = StubPasswordHasher()

        register = RegisterUser(repo, hasher)
        request = RegisterUserRequest(
            username="newuser",
            email="taken@example.com",
            password="SecurePass1",
        )

        with pytest.raises(RegistrationError, match="email already registered"):
            register.execute(request)

    def test_registration_with_weak_password(self) -> None:
        repo = StubUserRepository()
        hasher = StubPasswordHasher()

        register = RegisterUser(repo, hasher)
        request = RegisterUserRequest(
            username="newuser",
            email="new@example.com",
            password="short",
        )

        with pytest.raises(PasswordValidationError):
            register.execute(request)

    def test_registration_with_no_uppercase_password(self) -> None:
        repo = StubUserRepository()
        hasher = StubPasswordHasher()

        register = RegisterUser(repo, hasher)
        request = RegisterUserRequest(
            username="newuser",
            email="new@example.com",
            password="nouppercase1",
        )

        with pytest.raises(PasswordValidationError, match="uppercase"):
            register.execute(request)

    def test_registration_with_no_digit_password(self) -> None:
        repo = StubUserRepository()
        hasher = StubPasswordHasher()

        register = RegisterUser(repo, hasher)
        request = RegisterUserRequest(
            username="newuser",
            email="new@example.com",
            password="NoDigitHere",
        )

        with pytest.raises(PasswordValidationError, match="digit"):
            register.execute(request)

    def test_registration_with_invalid_role(self) -> None:
        repo = StubUserRepository()
        hasher = StubPasswordHasher()

        register = RegisterUser(repo, hasher)
        request = RegisterUserRequest(
            username="newuser",
            email="new@example.com",
            password="SecurePass1",
            role="superadmin",
        )

        with pytest.raises(RegistrationError, match="invalid role"):
            register.execute(request)

    def test_registration_default_role_is_viewer(self) -> None:
        repo = StubUserRepository()
        hasher = StubPasswordHasher()

        register = RegisterUser(repo, hasher)
        request = RegisterUserRequest(
            username="newuser",
            email="new@example.com",
            password="SecurePass1",
        )
        result = register.execute(request)

        assert result.role == "Viewer"
