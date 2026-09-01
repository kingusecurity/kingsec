"""Tests for RegisterUser use case."""

from __future__ import annotations

import pytest

from kingsec.application.dto import RegisterUserRequest
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

    def save_new_user_claiming_bootstrap_admin(self, user: User) -> User:
        if len(self.saved_users) == 0:
            user = User(
                id=user.id,
                username=user.username,
                email=user.email,
                password_hash=user.password_hash,
                role=Role.ADMIN,
                is_active=user.is_active,
                created_at=user.created_at,
                last_login_at=user.last_login_at,
            )
        self.saved_users.append(user)
        return user

    def exists_by_username(self, username: str) -> bool:
        return self._existing_username is not None and username.lower() == self._existing_username.lower()

    def exists_by_email(self, email: str) -> bool:
        return self._existing_email is not None and email.lower() == self._existing_email.lower()

    def list_all(self, limit: int = 50, offset: int = 0) -> list[User]:
        return []

    def count(self) -> int:
        return len(self.saved_users)

    def count_by_role(self, role: Role) -> int:
        return sum(1 for u in self.saved_users if u.role == role)

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
        )
        result = register.execute(request)

        assert result.username == "newuser"
        assert result.email == "new@example.com"
        assert result.role == "Admin"
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

        with pytest.raises(RegistrationError, match="username or email already in use"):
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

        with pytest.raises(RegistrationError, match="username or email already in use"):
            register.execute(request)

    def test_duplicate_username_and_duplicate_email_are_indistinguishable(self) -> None:
        """KSEC-86-03 (registration enumeration, Phase-84 carry-forward):
        the whole point of the generic message is that an unauthenticated
        caller cannot tell WHICH field collided - assert the two failure
        messages are byte-for-byte identical, not merely that each
        contains a generic-sounding substring."""
        hasher = StubPasswordHasher()

        username_conflict_repo = StubUserRepository(existing_username="taken")
        with pytest.raises(RegistrationError) as username_exc:
            RegisterUser(username_conflict_repo, hasher).execute(
                RegisterUserRequest(username="taken", email="new@example.com", password="SecurePass1")
            )

        email_conflict_repo = StubUserRepository(existing_email="taken@example.com")
        with pytest.raises(RegistrationError) as email_exc:
            RegisterUser(email_conflict_repo, hasher).execute(
                RegisterUserRequest(username="newuser", email="taken@example.com", password="SecurePass1")
            )

        assert str(username_exc.value) == str(email_exc.value), (
            "the response must not reveal which field (username vs email) actually collided"
        )

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

    def test_second_user_becomes_viewer(self) -> None:
        repo = StubUserRepository()
        hasher = StubPasswordHasher()

        # First user becomes ADMIN.
        register = RegisterUser(repo, hasher)
        first_req = RegisterUserRequest(
            username="admin",
            email="admin@example.com",
            password="SecurePass1",
        )
        first_result = register.execute(first_req)
        assert first_result.role == "Admin"

        # Second user becomes VIEWER.
        second_req = RegisterUserRequest(
            username="viewer",
            email="viewer@example.com",
            password="SecurePass1",
        )
        second_result = register.execute(second_req)
        assert second_result.role == "Viewer"

    def test_first_user_is_admin_on_empty_database(self) -> None:
        repo = StubUserRepository()
        hasher = StubPasswordHasher()

        register = RegisterUser(repo, hasher)
        request = RegisterUserRequest(
            username="first",
            email="first@example.com",
            password="SecurePass1",
        )
        result = register.execute(request)

        assert result.role == "Admin"
        assert repo.saved_users[0].role == Role.ADMIN

    def test_third_user_becomes_viewer(self) -> None:
        repo = StubUserRepository()
        hasher = StubPasswordHasher()

        register = RegisterUser(repo, hasher)
        for i in range(3):
            result = register.execute(
                RegisterUserRequest(
                    username=f"user{i}",
                    email=f"user{i}@example.com",
                    password="SecurePass1",
                )
            )
            expected = "Admin" if i == 0 else "Viewer"
            assert result.role == expected, f"user{i}: expected {expected}, got {result.role}"
