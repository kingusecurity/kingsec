"""Tests for the admin user-management use cases (admin_users.py).

KSEC-75-02: DeactivateUser previously set is_active=False and saved the
user, but never revoked the target's existing sessions/tokens - an
already-issued access token kept authenticating (JWT auth trusts the
token's own claims, not a fresh is_active lookup) until its own natural
expiry. The fix reuses RevokeAllSessions, the same mechanism
KSEC-73-01/KSEC-75-01 already use, rather than a second, parallel
revocation mechanism.

No test file previously existed for DeactivateUser/ActivateUser at all
(confirmed via a repository-wide grep before writing this file) - this
adds the first coverage for both, focused on the KSEC-75-02 remediation.
"""

from __future__ import annotations

import pytest
from tests.unit.application.test_session_use_cases import FakeSessionRepository, FakeTokenService

from kingsec.application.ports import AuditPublisher, UserRepository
from kingsec.application.use_cases.admin_users import (
    ActivateUser,
    ActivateUserRequest,
    DeactivateUser,
    DeactivateUserRequest,
)
from kingsec.application.use_cases.revoke_all_sessions import RevokeAllSessions
from kingsec.domain import Role, User
from kingsec.domain.audit import AuditEntry
from kingsec.domain.session import DeviceInfo, Session, SessionId, SessionStatus, SessionType
from kingsec.domain.user import UserNotFoundError

# --- Stubs (same shape as sibling admin_users test files) -------------------


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
        password_hash="hashed:password",
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


def _make_deactivate_user(
    repo: StubUserRepository, audit: StubAuditPublisher
) -> tuple[DeactivateUser, FakeSessionRepository, FakeTokenService]:
    """Build a real DeactivateUser wired to a real RevokeAllSessions -
    the exact mechanism KSEC-75-02 requires reusing."""
    session_repo = FakeSessionRepository()
    tokens = FakeTokenService()
    sessions_uc = RevokeAllSessions(session_repo, tokens)
    return DeactivateUser(repo, sessions_uc, audit), session_repo, tokens


class TestDeactivateUser:
    def test_deactivation_sets_is_active_false(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        audit = StubAuditPublisher()
        use_case, _session_repo, _tokens = _make_deactivate_user(repo, audit)

        result = use_case.execute(DeactivateUserRequest(user_id="user-001", admin_user_id="admin-001"))

        assert result.is_active is False
        assert repo.saved_users[0].is_active is False

    def test_nonexistent_user_raises_not_found(self) -> None:
        repo = StubUserRepository(user=None)
        audit = StubAuditPublisher()
        use_case, _session_repo, _tokens = _make_deactivate_user(repo, audit)

        with pytest.raises(UserNotFoundError):
            use_case.execute(DeactivateUserRequest(user_id="nonexistent", admin_user_id="admin-001"))

        assert repo.saved_users == []

    def test_audit_entry_is_recorded_on_success(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        audit = StubAuditPublisher()
        use_case, _session_repo, _tokens = _make_deactivate_user(repo, audit)

        use_case.execute(DeactivateUserRequest(user_id="user-001", admin_user_id="admin-001"))

        assert len(audit.entries) == 1
        assert audit.entries[0].resource_id == "user-001"


class TestDeactivateUserRevokesOutstandingSessions:
    """KSEC-75-02: deactivating a user must revoke every outstanding
    session/token for that user - proven against the real
    RevokeAllSessions use case, not a mock of the security control."""

    def test_successful_deactivation_revokes_all_sessions_and_tokens(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        audit = StubAuditPublisher()
        use_case, session_repo, tokens = _make_deactivate_user(repo, audit)

        session_repo.save(_make_session("user-001", "sess-1", "jti-access-1", "jti-refresh-1"))
        session_repo.save(_make_session("user-001", "sess-2", "jti-access-2", "jti-refresh-2"))

        use_case.execute(DeactivateUserRequest(user_id="user-001", admin_user_id="admin-001"))

        assert session_repo.sessions["sess-1"].status == SessionStatus.REVOKED
        assert session_repo.sessions["sess-2"].status == SessionStatus.REVOKED
        assert tokens.is_revoked("jti-access-1")
        assert tokens.is_revoked("jti-refresh-1")
        assert tokens.is_revoked("jti-access-2")
        assert tokens.is_revoked("jti-refresh-2")

    def test_failed_deactivation_does_not_revoke_any_session(self) -> None:
        repo = StubUserRepository(user=None)
        audit = StubAuditPublisher()
        use_case, session_repo, tokens = _make_deactivate_user(repo, audit)

        session_repo.save(_make_session("user-001", "sess-1", "jti-access-1", "jti-refresh-1"))

        with pytest.raises(UserNotFoundError):
            use_case.execute(DeactivateUserRequest(user_id="user-001", admin_user_id="admin-001"))

        assert session_repo.sessions["sess-1"].status == SessionStatus.ACTIVE
        assert not tokens.is_revoked("jti-access-1")

    def test_admin_performing_the_deactivation_does_not_have_their_own_sessions_revoked(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        audit = StubAuditPublisher()
        use_case, session_repo, tokens = _make_deactivate_user(repo, audit)

        session_repo.save(_make_session("user-001", "sess-target", "jti-access-target", "jti-refresh-target"))
        session_repo.save(_make_session("admin-001", "sess-admin", "jti-access-admin", "jti-refresh-admin"))

        use_case.execute(DeactivateUserRequest(user_id="user-001", admin_user_id="admin-001"))

        assert session_repo.sessions["sess-target"].status == SessionStatus.REVOKED
        assert session_repo.sessions["sess-admin"].status == SessionStatus.ACTIVE
        assert not tokens.is_revoked("jti-access-admin")

    def test_another_unrelated_users_sessions_are_unaffected(self) -> None:
        user = _make_user()
        repo = StubUserRepository(user)
        audit = StubAuditPublisher()
        use_case, session_repo, tokens = _make_deactivate_user(repo, audit)

        session_repo.save(_make_session("user-001", "sess-target", "jti-access-target", "jti-refresh-target"))
        session_repo.save(_make_session("user-999", "sess-other", "jti-access-other", "jti-refresh-other"))

        use_case.execute(DeactivateUserRequest(user_id="user-001", admin_user_id="admin-001"))

        assert session_repo.sessions["sess-target"].status == SessionStatus.REVOKED
        assert session_repo.sessions["sess-other"].status == SessionStatus.ACTIVE
        assert not tokens.is_revoked("jti-access-other")


class TestActivateUser:
    """Baseline coverage for the sibling use case - unmodified by
    KSEC-75-02, included so reactivation semantics have at least one
    regression test guarding them."""

    def test_activation_sets_is_active_true(self) -> None:
        user = _make_user(is_active=False)
        repo = StubUserRepository(user)
        audit = StubAuditPublisher()
        use_case = ActivateUser(repo, audit)

        result = use_case.execute(ActivateUserRequest(user_id="user-001", admin_user_id="admin-001"))

        assert result.is_active is True
        assert repo.saved_users[0].is_active is True

    def test_nonexistent_user_raises_not_found(self) -> None:
        repo = StubUserRepository(user=None)
        audit = StubAuditPublisher()
        use_case = ActivateUser(repo, audit)

        with pytest.raises(UserNotFoundError):
            use_case.execute(ActivateUserRequest(user_id="nonexistent", admin_user_id="admin-001"))
