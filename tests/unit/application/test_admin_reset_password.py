"""Tests for AdminResetPassword use case.

Phase 67 / Finding KSEC-64-03: AdminResetPassword.execute() previously
hashed and stored request.new_password directly, with no call to any
password-complexity validator anywhere in the stack - an admin could set
another user's password to "" or any arbitrarily weak string, unlike
every other password-setting path (RegisterUser, ChangePassword), which
already enforce the same 5-rule policy (8-128 chars, upper/lower/digit).
The fix reuses ChangePassword._validate_password() directly rather than
duplicating those rules a third time.
"""

from __future__ import annotations

import pytest

from kingsec.application.ports import AuditPublisher, PasswordHasher, UserRepository
from kingsec.application.use_cases.admin_users import AdminResetPassword, ResetPasswordRequest
from kingsec.domain import Role, User
from kingsec.domain.audit import AuditEntry
from kingsec.domain.user import PasswordValidationError, UserNotFoundError

# --- Stubs (same shape as test_change_password.py's, reused rather than
#     redefined differently) ---------------------------------------------


class StubPasswordHasher(PasswordHasher):
    def __init__(self) -> None:
        self.hashed_passwords: list[str] = []

    def hash(self, password: str) -> str:
        self.hashed_passwords.append(password)
        return f"hashed:{password}"

    def verify(self, password: str, password_hash: str) -> bool:
        return password_hash == f"hashed:{password}"


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

    def save_new_user_claiming_bootstrap_admin(self, user: User) -> User:
        self.saved_users.append(user)
        return user

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


class StubAuditPublisher(AuditPublisher):
    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        self.entries.append(entry)


def _make_user(**kwargs) -> User:
    defaults = dict(
        id="user-001",
        username="targetuser",
        email="target@example.com",
        password_hash="hashed:originalpassword",
        role=Role.VIEWER,
    )
    defaults.update(kwargs)
    return User(**defaults)


def _make_request(new_password: str) -> ResetPasswordRequest:
    return ResetPasswordRequest(
        user_id="user-001",
        new_password=new_password,
        admin_user_id="admin-001",
        admin_username="admin",
    )


class TestAdminResetPasswordComplexity:
    """The core KSEC-64-03 regression coverage: the admin path must agree
    with the canonical policy on every tested password."""

    @pytest.mark.parametrize(
        "weak_password",
        [
            "",
            "short1A",  # 7 chars, one under the 8-char minimum
            "alllowercase1",  # no uppercase
            "ALLUPPERCASE1",  # no lowercase
            "NoDigitsHere",  # no digit
            "x" * 129 + "A1",  # over the 128-char maximum
        ],
    )
    def test_weak_password_is_rejected(self, weak_password: str) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher()
        audit = StubAuditPublisher()

        use_case = AdminResetPassword(repo, hasher, audit)

        with pytest.raises(PasswordValidationError):
            use_case.execute(_make_request(weak_password))

        # Negative security evidence: no hash was generated and the
        # existing credential on the target user's record is unchanged.
        assert hasher.hashed_passwords == []
        assert repo.saved_users == []
        assert user.password_hash == "hashed:originalpassword"

    def test_valid_password_accepted_by_the_canonical_policy_succeeds(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher()
        audit = StubAuditPublisher()

        use_case = AdminResetPassword(repo, hasher, audit)
        result = use_case.execute(_make_request("NewSecurePass1"))

        assert result.user_id == "user-001"
        assert hasher.hashed_passwords == ["NewSecurePass1"]
        assert len(repo.saved_users) == 1
        # The stored credential is the hash, never the plaintext.
        assert repo.saved_users[0].password_hash == "hashed:NewSecurePass1"
        assert repo.saved_users[0].password_hash != "NewSecurePass1"

    def test_audit_entry_is_recorded_on_success(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher()
        audit = StubAuditPublisher()

        AdminResetPassword(repo, hasher, audit).execute(_make_request("NewSecurePass1"))

        assert len(audit.entries) == 1
        assert audit.entries[0].resource_id == "user-001"

    def test_nonexistent_target_user_raises_not_found_before_any_hashing(self) -> None:
        repo = StubUserRepository(user=None)
        hasher = StubPasswordHasher()
        audit = StubAuditPublisher()

        with pytest.raises(UserNotFoundError):
            AdminResetPassword(repo, hasher, audit).execute(_make_request("NewSecurePass1"))

        assert hasher.hashed_passwords == []
        assert repo.saved_users == []
