"""Tests for the AssignRole use case."""

from __future__ import annotations

import uuid

import pytest

from kingsec.application.dto import AssignRoleRequest
from kingsec.application.ports import AuditPublisher, UserRepository
from kingsec.application.use_cases.assign_role import AssignRole, AssignRoleError
from kingsec.domain import Role
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


class TestAssignRole:
    def test_admin_can_assign_role(self) -> None:
        repo = StubUserRepository()
        admin = _make_user(role=Role.ADMIN)
        target = _make_user(role=Role.VIEWER)
        repo.add_user(admin)
        repo.add_user(target)
        use_case = AssignRole(repo)

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
        use_case = AssignRole(repo)

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
        use_case = AssignRole(repo)

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
        use_case = AssignRole(repo)

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
        use_case = AssignRole(repo)

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
        use_case = AssignRole(repo)

        with pytest.raises(AssignRoleError, match="already has role"):
            use_case.execute(AssignRoleRequest(
                requesting_user_id=admin.id,
                target_user_id=target.id,
                new_role="Viewer",
            ))

    def test_publishes_audit_event(self) -> None:
        repo = StubUserRepository()
        audit = StubAuditPublisher()
        admin = _make_user(role=Role.ADMIN)
        target = _make_user(role=Role.VIEWER)
        repo.add_user(admin)
        repo.add_user(target)
        use_case = AssignRole(repo, audit=audit)

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
