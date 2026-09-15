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
from tests.unit.application.test_session_use_cases import FakeSessionRepository, FakeTokenService

from kingsec.application.ports import AuditPublisher, PasswordHasher, UserRepository
from kingsec.application.use_cases.admin_users import AdminResetPassword, ResetPasswordRequest
from kingsec.application.use_cases.revoke_all_sessions import RevokeAllSessions
from kingsec.domain import Role, User
from kingsec.domain.audit import AuditEntry
from kingsec.domain.session import DeviceInfo, Session, SessionId, SessionStatus, SessionType
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

    def save_new_user(self, user: User) -> User:
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


def _make_request(new_password: str, user_id: str = "user-001") -> ResetPasswordRequest:
    return ResetPasswordRequest(
        user_id=user_id,
        new_password=new_password,
        admin_user_id="admin-001",
        admin_username="admin",
    )


def _make_session(user_id: str, session_id: str, jti: str, refresh_jti: str) -> Session:
    return Session(
        id=SessionId(value=session_id),
        user_id=user_id,
        session_type=SessionType.USER,
        jti=jti,
        refresh_jti=refresh_jti,
        issued_at="2026-01-01T00:00:00",
        expires_at="2026-01-08T00:00:00",
        last_activity="2026-01-01T00:00:00",
        client_ip="",
        user_agent="",
        device_info=DeviceInfo(),
        status=SessionStatus.ACTIVE,
    )


def _make_admin_reset_password(
    repo: StubUserRepository,
    hasher: StubPasswordHasher,
    audit: StubAuditPublisher,
) -> tuple[AdminResetPassword, FakeSessionRepository, FakeTokenService]:
    """Build a real AdminResetPassword wired to a real RevokeAllSessions -
    the exact mechanism KSEC-75-01 requires reusing (the same one
    KSEC-73-01's self-service ChangePassword already uses)."""
    session_repo = FakeSessionRepository()
    tokens = FakeTokenService()
    sessions_uc = RevokeAllSessions(session_repo, tokens)
    return AdminResetPassword(repo, hasher, sessions_uc, audit), session_repo, tokens


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

        use_case, _session_repo, _tokens = _make_admin_reset_password(repo, hasher, audit)

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

        use_case, _session_repo, _tokens = _make_admin_reset_password(repo, hasher, audit)
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

        use_case, _session_repo, _tokens = _make_admin_reset_password(repo, hasher, audit)
        use_case.execute(_make_request("NewSecurePass1"))

        assert len(audit.entries) == 1
        assert audit.entries[0].resource_id == "user-001"

    def test_nonexistent_target_user_raises_not_found_before_any_hashing(self) -> None:
        repo = StubUserRepository(user=None)
        hasher = StubPasswordHasher()
        audit = StubAuditPublisher()

        use_case, _session_repo, _tokens = _make_admin_reset_password(repo, hasher, audit)
        with pytest.raises(UserNotFoundError):
            use_case.execute(_make_request("NewSecurePass1"))

        assert hasher.hashed_passwords == []
        assert repo.saved_users == []


class TestAdminResetPasswordRevokesOutstandingSessions:
    """KSEC-75-01: an admin-initiated password reset must revoke every
    outstanding session/token for the TARGET user - the incident-
    response tool for a compromised account must actually cut the
    attacker off - proven against the real RevokeAllSessions use case,
    not a mock of the security control itself."""

    def test_successful_reset_revokes_target_users_sessions_and_tokens(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher()
        audit = StubAuditPublisher()
        use_case, session_repo, tokens = _make_admin_reset_password(repo, hasher, audit)

        session_repo.save(_make_session("user-001", "sess-1", "jti-access-1", "jti-refresh-1"))
        session_repo.save(_make_session("user-001", "sess-2", "jti-access-2", "jti-refresh-2"))

        use_case.execute(_make_request("NewSecurePass1"))

        assert session_repo.sessions["sess-1"].status == SessionStatus.REVOKED
        assert session_repo.sessions["sess-2"].status == SessionStatus.REVOKED
        assert tokens.is_revoked("jti-access-1")
        assert tokens.is_revoked("jti-refresh-1")
        assert tokens.is_revoked("jti-access-2")
        assert tokens.is_revoked("jti-refresh-2")

    def test_failed_reset_does_not_revoke_any_session(self) -> None:
        """A rejected reset attempt (weak password) must not revoke the
        target's real sessions."""
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher()
        audit = StubAuditPublisher()
        use_case, session_repo, tokens = _make_admin_reset_password(repo, hasher, audit)

        session_repo.save(_make_session("user-001", "sess-1", "jti-access-1", "jti-refresh-1"))

        with pytest.raises(PasswordValidationError):
            use_case.execute(_make_request("weak"))

        assert session_repo.sessions["sess-1"].status == SessionStatus.ACTIVE
        assert not tokens.is_revoked("jti-access-1")
        assert not tokens.is_revoked("jti-refresh-1")

    def test_admin_performing_the_reset_does_not_have_their_own_sessions_revoked(self) -> None:
        """The admin issuing the reset must never have their own,
        unrelated sessions touched - only the target user's."""
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher()
        audit = StubAuditPublisher()
        use_case, session_repo, tokens = _make_admin_reset_password(repo, hasher, audit)

        session_repo.save(_make_session("user-001", "sess-target", "jti-access-target", "jti-refresh-target"))
        session_repo.save(_make_session("admin-001", "sess-admin", "jti-access-admin", "jti-refresh-admin"))

        use_case.execute(_make_request("NewSecurePass1"))

        assert session_repo.sessions["sess-target"].status == SessionStatus.REVOKED
        assert session_repo.sessions["sess-admin"].status == SessionStatus.ACTIVE
        assert not tokens.is_revoked("jti-access-admin")
        assert not tokens.is_revoked("jti-refresh-admin")

    def test_another_unrelated_users_sessions_are_unaffected(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher()
        audit = StubAuditPublisher()
        use_case, session_repo, tokens = _make_admin_reset_password(repo, hasher, audit)

        session_repo.save(_make_session("user-001", "sess-target", "jti-access-target", "jti-refresh-target"))
        session_repo.save(_make_session("user-999", "sess-other", "jti-access-other", "jti-refresh-other"))

        use_case.execute(_make_request("NewSecurePass1"))

        assert session_repo.sessions["sess-target"].status == SessionStatus.REVOKED
        assert session_repo.sessions["sess-other"].status == SessionStatus.ACTIVE
        assert not tokens.is_revoked("jti-access-other")
        assert not tokens.is_revoked("jti-refresh-other")
