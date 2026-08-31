"""Tests for the SQLAlchemy user repository - KSEC-73-05.

Phase 74: the first-user-becomes-admin bootstrap must be an atomic
persistence-layer claim, not a Python-level "count users, then insert
later" check. These tests exercise the REAL SqlAlchemyUserRepository
against a real on-disk SQLite database, including a genuine
multi-threaded concurrency test, per the explicit requirement to
exercise the actual persistence mechanism as far as the existing test
architecture allows.
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kingsec.domain import Role, User
from kingsec.infrastructure.persistence.models import Base
from kingsec.infrastructure.persistence.user_repository import SqlAlchemyUserRepository


@pytest.fixture
def engine(tmp_path: Path):
    """A real on-disk SQLite database file with SQLAlchemy's default
    connection pooling, so each thread gets its own independent DBAPI
    connection subject to SQLite's own file-level locking - see the
    identical rationale in test_recovery_code_repository.py's ``engine``
    fixture for why a single shared StaticPool connection was rejected.
    """
    db_path = tmp_path / f"users-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(
        f"sqlite:///{db_path}",
        future=True,
        connect_args={"timeout": 30},
    )
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def repo(session_factory) -> SqlAlchemyUserRepository:
    return SqlAlchemyUserRepository(session_factory)


def _make_user(**kwargs) -> User:
    suffix = uuid.uuid4().hex[:8]
    defaults: dict = dict(
        id=str(uuid.uuid4()),
        username=f"user_{suffix}",
        email=f"user_{suffix}@example.com",
        password_hash="hashed:password",
        role=Role.VIEWER,
    )
    defaults.update(kwargs)
    return User(**defaults)


class TestSqlAlchemyUserRepositoryBootstrapAdmin:
    def test_first_user_on_empty_database_becomes_admin(self, repo: SqlAlchemyUserRepository) -> None:
        user = _make_user(role=Role.VIEWER)

        persisted = repo.save_new_user_claiming_bootstrap_admin(user)

        assert persisted.role == Role.ADMIN
        stored = repo.find_by_id(user.id)
        assert stored is not None
        assert stored.role == Role.ADMIN

    def test_second_user_after_bootstrap_keeps_requested_role(self, repo: SqlAlchemyUserRepository) -> None:
        first = _make_user(role=Role.VIEWER)
        repo.save_new_user_claiming_bootstrap_admin(first)

        second = _make_user(role=Role.VIEWER)
        persisted = repo.save_new_user_claiming_bootstrap_admin(second)

        assert persisted.role == Role.VIEWER
        stored = repo.find_by_id(second.id)
        assert stored is not None
        assert stored.role == Role.VIEWER

    def test_normal_registration_after_bootstrap_remains_correct(self, repo: SqlAlchemyUserRepository) -> None:
        """A third registration, well after bootstrap, still correctly
        receives the non-admin default role - the atomic claim only ever
        fires once, on a genuinely empty table."""
        repo.save_new_user_claiming_bootstrap_admin(_make_user(role=Role.VIEWER))
        repo.save_new_user_claiming_bootstrap_admin(_make_user(role=Role.VIEWER))
        third = _make_user(role=Role.VIEWER)

        persisted = repo.save_new_user_claiming_bootstrap_admin(third)

        assert persisted.role == Role.VIEWER
        assert repo.count() == 3
        assert repo.count_by_role(Role.ADMIN) == 1

    def test_concurrent_registrations_against_empty_table_exactly_one_becomes_admin(
        self, repo: SqlAlchemyUserRepository
    ) -> None:
        """KSEC-73-05's actual security invariant, under real concurrency:
        two registrations racing the bootstrap slot on a genuinely empty
        table must result in exactly one ADMIN and exactly one VIEWER -
        never two ADMINs, never zero, and the table must not end up
        corrupted (missing rows, duplicate ids, etc).
        """
        user_a = _make_user(role=Role.VIEWER)
        user_b = _make_user(role=Role.VIEWER)

        barrier = threading.Barrier(2)
        results: dict[str, Role] = {}
        errors: dict[str, BaseException] = {}

        def attempt(name: str, user: User) -> None:
            barrier.wait()  # force both threads to race the same INSERT...SELECT together
            try:
                persisted = repo.save_new_user_claiming_bootstrap_admin(user)
                results[name] = persisted.role
            except BaseException as exc:
                errors[name] = exc

        t1 = threading.Thread(target=attempt, args=("request-A", user_a))
        t2 = threading.Thread(target=attempt, args=("request-B", user_b))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert errors == {}, f"unexpected exception(s) during concurrent bootstrap claim: {errors!r}"
        assert set(results.keys()) == {"request-A", "request-B"}

        roles = sorted(role.value for role in results.values())
        assert roles == sorted([Role.ADMIN.value, Role.VIEWER.value]), (
            f"expected exactly one ADMIN and one VIEWER, got {results!r} - if both are ADMIN, the "
            "bootstrap claim is not atomic and KSEC-73-05's race has reopened"
        )

        # Both rows persisted correctly - no corruption, no lost writes.
        assert repo.count() == 2
        assert repo.count_by_role(Role.ADMIN) == 1
        assert repo.count_by_role(Role.VIEWER) == 1
