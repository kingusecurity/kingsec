"""Tests for the AssignRole use case."""

from __future__ import annotations

import uuid

import pytest
from tests.unit.application.test_session_use_cases import FakeSessionRepository, FakeTokenService

from kingsec.application.dto import AssignRoleRequest
from kingsec.application.ports import AuditPublisher, UserRepository
from kingsec.application.use_cases.assign_role import AssignRole, AssignRoleError
from kingsec.application.use_cases.revoke_all_sessions import RevokeAllSessions
from kingsec.domain import Role
from kingsec.domain.session import DeviceInfo, Session, SessionId, SessionStatus, SessionType
from kingsec.domain.user import User


class StubUserRepository(UserRepository):
    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    def add_user(self, user: User) -> None:
        self._users[user.id] = user

    def find_by_username(self, username: str) -> User | None:
        return next((u for u in self._users.values() if u.username == username), None)

    def find_by_id(self, user_id: str) -> User | None:
        return self._users.get(user_id)

    def save(self, user: User) -> None:
        self._users[user.id] = user

    def save_new_user_claiming_bootstrap_admin(self, user: User) -> User:
        self._users[user.id] = user
        return user

    def exists_by_username(self, username: str) -> bool:
        return any(u.username == username for u in self._users.values())

    def exists_by_email(self, email: str) -> bool:
        return any(u.email == email for u in self._users.values())

    def list_all(self, limit: int = 50, offset: int = 0) -> list[User]:
        return list(self._users.values())

    def count(self) -> int:
        return len(self._users)

    def count_by_role(self, role: Role) -> int:
        return sum(1 for u in self._users.values() if u.role == role)

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
        self.entries: list = []

    def record(self, entry: object) -> None:
        self.entries.append(entry)


def _make_user(*, role: Role = Role.VIEWER) -> User:
    suffix = uuid.uuid4().hex[:6]
    return User(
        id=str(uuid.uuid4()),
        username=f"user_{suffix}",
        email=f"user_{suffix}@example.com",
        password_hash="hashed:password",
        role=role,
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


def _make_assign_role(
    repo: StubUserRepository, audit: StubAuditPublisher | None = None
) -> tuple[AssignRole, FakeSessionRepository, FakeTokenService]:
    """Build a real AssignRole wired to a real RevokeAllSessions - the
    exact mechanism KSEC-75-03 requires reusing."""
    session_repo = FakeSessionRepository()
    tokens = FakeTokenService()
    sessions_uc = RevokeAllSessions(session_repo, tokens)
    return AssignRole(repo, sessions_uc, audit=audit), session_repo, tokens


class TestAssignRole:
    def test_admin_can_assign_role(self) -> None:
        repo = StubUserRepository()
        admin = _make_user(role=Role.ADMIN)
        target = _make_user(role=Role.VIEWER)
        repo.add_user(admin)
        repo.add_user(target)
        use_case, _session_repo, _tokens = _make_assign_role(repo)

        result = use_case.execute(AssignRoleRequest(
            requesting_user_id=admin.id,
            target_user_id=target.id,
            new_role="analyst",
        ))

        assert result.user_id == target.id
        assert result.new_role == "Analyst"
        assert repo.find_by_id(target.id).role == Role.ANALYST

    def test_non_admin_cannot_assign_role(self) -> None:
        repo = StubUserRepository()
        viewer = _make_user(role=Role.VIEWER)
        target = _make_user(role=Role.VIEWER)
        repo.add_user(viewer)
        repo.add_user(target)
        use_case, _session_repo, _tokens = _make_assign_role(repo)

        with pytest.raises(AssignRoleError, match="insufficient permissions"):
            use_case.execute(AssignRoleRequest(
                requesting_user_id=viewer.id,
                target_user_id=target.id,
                new_role="analyst",
            ))

    def test_cannot_demote_last_admin(self) -> None:
        repo = StubUserRepository()
        admin = _make_user(role=Role.ADMIN)
        repo.add_user(admin)
        use_case, _session_repo, _tokens = _make_assign_role(repo)

        with pytest.raises(AssignRoleError, match="cannot demote the last administrator"):
            use_case.execute(AssignRoleRequest(
                requesting_user_id=admin.id,
                target_user_id=admin.id,
                new_role="viewer",
            ))

    def test_can_demote_admin_when_another_exists(self) -> None:
        repo = StubUserRepository()
        admin1 = _make_user(role=Role.ADMIN)
        admin2 = _make_user(role=Role.ADMIN)
        repo.add_user(admin1)
        repo.add_user(admin2)
        use_case, _session_repo, _tokens = _make_assign_role(repo)

        result = use_case.execute(AssignRoleRequest(
            requesting_user_id=admin1.id,
            target_user_id=admin2.id,
            new_role="analyst",
        ))

        assert result.new_role == "Analyst"
        assert repo.find_by_id(admin2.id).role == Role.ANALYST

    def test_invalid_role_rejected(self) -> None:
        repo = StubUserRepository()
        admin = _make_user(role=Role.ADMIN)
        repo.add_user(admin)
        use_case, _session_repo, _tokens = _make_assign_role(repo)

        with pytest.raises(AssignRoleError, match="invalid role"):
            use_case.execute(AssignRoleRequest(
                requesting_user_id=admin.id,
                target_user_id=admin.id,
                new_role="superadmin",
            ))

    def test_same_role_rejected(self) -> None:
        repo = StubUserRepository()
        admin = _make_user(role=Role.ADMIN)
        target = _make_user(role=Role.VIEWER)
        repo.add_user(admin)
        repo.add_user(target)
        use_case, session_repo, tokens = _make_assign_role(repo)

        session_repo.save(_make_session(target.id, "sess-target", "jti-target", "rjti-target"))

        with pytest.raises(AssignRoleError, match="already has role"):
            use_case.execute(AssignRoleRequest(
                requesting_user_id=admin.id,
                target_user_id=target.id,
                new_role="Viewer",
            ))

        # Same-role assignment is a rejected no-op (existing, unchanged
        # semantics) - it must not churn the target's sessions either.
        assert session_repo.sessions["sess-target"].status == SessionStatus.ACTIVE
        assert not tokens.is_revoked("jti-target")

    def test_publishes_audit_event(self) -> None:
        repo = StubUserRepository()
        audit = StubAuditPublisher()
        admin = _make_user(role=Role.ADMIN)
        target = _make_user(role=Role.VIEWER)
        repo.add_user(admin)
        repo.add_user(target)
        use_case, _session_repo, _tokens = _make_assign_role(repo, audit=audit)

        use_case.execute(AssignRoleRequest(
            requesting_user_id=admin.id,
            target_user_id=target.id,
            new_role="analyst",
        ))

        assert len(audit.entries) == 1
        entry = audit.entries[0]
        assert entry.action.value == "role_changed"
        assert entry.resource_id == target.id
        assert entry.metadata["new_role"] == "Analyst"


class TestAssignRoleRevokesOutstandingSessions:
    """KSEC-75-03: a role change (promotion or demotion) must revoke the
    target's existing sessions/tokens, so a stale JWT can never keep
    authenticating with the OLD role - proven against the real
    RevokeAllSessions use case, not a mock of the security control."""

    def test_demotion_revokes_target_sessions_and_tokens(self) -> None:
        repo = StubUserRepository()
        admin = _make_user(role=Role.ADMIN)
        target = _make_user(role=Role.ADMIN)  # will be demoted
        repo.add_user(admin)
        repo.add_user(target)
        use_case, session_repo, tokens = _make_assign_role(repo)

        session_repo.save(_make_session(target.id, "sess-1", "jti-access-1", "jti-refresh-1"))

        use_case.execute(AssignRoleRequest(
            requesting_user_id=admin.id,
            target_user_id=target.id,
            new_role="viewer",
        ))

        assert session_repo.sessions["sess-1"].status == SessionStatus.REVOKED
        assert tokens.is_revoked("jti-access-1")
        assert tokens.is_revoked("jti-refresh-1")

    def test_promotion_also_revokes_target_sessions_and_tokens(self) -> None:
        """Promotion must equally force a fresh session - an old,
        lower-privileged session must not be left alive just because
        the new role is MORE privileged."""
        repo = StubUserRepository()
        admin = _make_user(role=Role.ADMIN)
        target = _make_user(role=Role.VIEWER)  # will be promoted
        repo.add_user(admin)
        repo.add_user(target)
        use_case, session_repo, tokens = _make_assign_role(repo)

        session_repo.save(_make_session(target.id, "sess-1", "jti-access-1", "jti-refresh-1"))

        use_case.execute(AssignRoleRequest(
            requesting_user_id=admin.id,
            target_user_id=target.id,
            new_role="admin",
        ))

        assert session_repo.sessions["sess-1"].status == SessionStatus.REVOKED
        assert tokens.is_revoked("jti-access-1")
        assert tokens.is_revoked("jti-refresh-1")

    def test_failed_assignment_does_not_revoke_any_session(self) -> None:
        repo = StubUserRepository()
        viewer = _make_user(role=Role.VIEWER)
        target = _make_user(role=Role.VIEWER)
        repo.add_user(viewer)
        repo.add_user(target)
        use_case, session_repo, tokens = _make_assign_role(repo)

        session_repo.save(_make_session(target.id, "sess-1", "jti-access-1", "jti-refresh-1"))

        with pytest.raises(AssignRoleError, match="insufficient permissions"):
            use_case.execute(AssignRoleRequest(
                requesting_user_id=viewer.id,
                target_user_id=target.id,
                new_role="analyst",
            ))

        assert session_repo.sessions["sess-1"].status == SessionStatus.ACTIVE
        assert not tokens.is_revoked("jti-access-1")

    def test_admin_performing_the_assignment_does_not_have_their_own_sessions_revoked(self) -> None:
        repo = StubUserRepository()
        admin = _make_user(role=Role.ADMIN)
        target = _make_user(role=Role.VIEWER)
        repo.add_user(admin)
        repo.add_user(target)
        use_case, session_repo, tokens = _make_assign_role(repo)

        session_repo.save(_make_session(target.id, "sess-target", "jti-access-target", "jti-refresh-target"))
        session_repo.save(_make_session(admin.id, "sess-admin", "jti-access-admin", "jti-refresh-admin"))

        use_case.execute(AssignRoleRequest(
            requesting_user_id=admin.id,
            target_user_id=target.id,
            new_role="analyst",
        ))

        assert session_repo.sessions["sess-target"].status == SessionStatus.REVOKED
        assert session_repo.sessions["sess-admin"].status == SessionStatus.ACTIVE
        assert not tokens.is_revoked("jti-access-admin")
