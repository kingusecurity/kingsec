"""Tests for ChangePassword use case."""

from __future__ import annotations

import pytest
from tests.unit.application.test_session_use_cases import FakeSessionRepository, FakeTokenService

from kingsec.application.dto import ChangePasswordRequest
from kingsec.application.ports import PasswordHasher, UserRepository
from kingsec.application.use_cases.change_password import ChangePassword, PasswordChangeError
from kingsec.application.use_cases.revoke_all_sessions import RevokeAllSessions
from kingsec.domain import Role, User
from kingsec.domain.session import DeviceInfo, Session, SessionId, SessionStatus, SessionType
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


def _make_change_password(
    repo: StubUserRepository, hasher: StubPasswordHasher
) -> tuple[ChangePassword, FakeSessionRepository, FakeTokenService]:
    """Build a real ChangePassword wired to a real RevokeAllSessions -
    the exact mechanism KSEC-73-01 requires reusing - backed by the same
    fakes test_session_use_cases.py already uses for RevokeAllSessions
    itself."""
    session_repo = FakeSessionRepository()
    tokens = FakeTokenService()
    sessions_uc = RevokeAllSessions(session_repo, tokens)
    return ChangePassword(repo, hasher, sessions_uc), session_repo, tokens


# --- Tests --------------------------------------------------------------------


class TestChangePassword:
    def test_successful_password_change(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher(verify_result=True)
        change, _session_repo, _tokens = _make_change_password(repo, hasher)

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
        change, _session_repo, _tokens = _make_change_password(repo, hasher)

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
        change, _session_repo, _tokens = _make_change_password(repo, hasher)

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
        change, _session_repo, _tokens = _make_change_password(repo, hasher)

        request = ChangePasswordRequest(
            user_id="user-001",
            current_password="oldpassword",
            new_password="short",
        )

        with pytest.raises(PasswordValidationError):
            change.execute(request)


class TestChangePasswordRevokesOutstandingSessions:
    """KSEC-73-01: a successful password change must revoke every
    outstanding session/token for that user - proven against the real
    RevokeAllSessions use case, not a mock of the security control
    itself."""

    def test_successful_change_revokes_all_sessions_and_tokens(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher(verify_result=True)
        change, session_repo, tokens = _make_change_password(repo, hasher)

        session_repo.save(_make_session("user-001", "sess-1", "jti-access-1", "jti-refresh-1"))
        session_repo.save(_make_session("user-001", "sess-2", "jti-access-2", "jti-refresh-2"))

        change.execute(
            ChangePasswordRequest(user_id="user-001", current_password="oldpassword", new_password="NewSecurePass1")
        )

        # Both sessions revoked...
        assert session_repo.sessions["sess-1"].status == SessionStatus.REVOKED
        assert session_repo.sessions["sess-2"].status == SessionStatus.REVOKED
        # ...and both sessions' access AND refresh jtis are in the actual
        # token-revocation store the JWT-verification path consults.
        assert tokens.is_revoked("jti-access-1")
        assert tokens.is_revoked("jti-refresh-1")
        assert tokens.is_revoked("jti-access-2")
        assert tokens.is_revoked("jti-refresh-2")

    def test_failed_change_does_not_revoke_any_session(self) -> None:
        """A rejected password-change attempt (wrong current password)
        must not revoke the account's real sessions."""
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher(verify_result=False)
        change, session_repo, tokens = _make_change_password(repo, hasher)

        session_repo.save(_make_session("user-001", "sess-1", "jti-access-1", "jti-refresh-1"))

        with pytest.raises(PasswordChangeError):
            change.execute(
                ChangePasswordRequest(user_id="user-001", current_password="wrongpassword", new_password="NewSecurePass1")
            )

        assert session_repo.sessions["sess-1"].status == SessionStatus.ACTIVE
        assert not tokens.is_revoked("jti-access-1")
        assert not tokens.is_revoked("jti-refresh-1")

    def test_another_users_sessions_are_unaffected(self) -> None:
        """A password change for one user must not touch a different
        user's sessions/tokens."""
        user = _make_user()
        repo = StubUserRepository(user)
        hasher = StubPasswordHasher(verify_result=True)
        change, session_repo, tokens = _make_change_password(repo, hasher)

        session_repo.save(_make_session("user-001", "sess-mine", "jti-access-mine", "jti-refresh-mine"))
        session_repo.save(_make_session("user-999", "sess-other", "jti-access-other", "jti-refresh-other"))

        change.execute(
            ChangePasswordRequest(user_id="user-001", current_password="oldpassword", new_password="NewSecurePass1")
        )

        assert session_repo.sessions["sess-mine"].status == SessionStatus.REVOKED
        assert session_repo.sessions["sess-other"].status == SessionStatus.ACTIVE
        assert not tokens.is_revoked("jti-access-other")
        assert not tokens.is_revoked("jti-refresh-other")
