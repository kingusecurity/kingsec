"""Tests for the SQLAlchemy user repository.

Phase 3 (auth hardening): KSEC-73-05's atomic first-user-becomes-admin
bootstrap claim (Phase 74) has been removed entirely - an unauthenticated
caller winning the race to be first through /auth/register on a
network-reachable instance could permanently own the system. The initial
admin is now created only by kingsec-bootstrap
(src/kingsec/_bootstrap.py), never by save_new_user. These tests exercise
the REAL SqlAlchemyUserRepository.save_new_user against a real on-disk
SQLite database, confirming it is now a PLAIN insert - the role persisted
is always exactly the role given, regardless of how many rows already
exist or how many callers race it concurrently. This file is the only
real-database test coverage for SqlAlchemyUserRepository, so it is
rewritten to match the new contract rather than deleted outright.
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


class TestSqlAlchemyUserRepositorySaveNewUser:
    def test_first_user_on_empty_database_persists_with_role_exactly_as_given(
        self, repo: SqlAlchemyUserRepository
    ) -> None:
        """Phase 3: the exact vulnerability this phase closes, verified
        against the real repository. Before this fix, the first row ever
        inserted into an empty table was atomically overridden to ADMIN
        (KSEC-73-05). save_new_user must never do that again - the first
        user, same as every other, gets exactly the role it was given."""
        user = _make_user(role=Role.VIEWER)

        persisted = repo.save_new_user(user)

        assert persisted.role == Role.VIEWER
        stored = repo.find_by_id(user.id)
        assert stored is not None
        assert stored.role == Role.VIEWER

    def test_role_is_never_overridden_regardless_of_table_state(self, repo: SqlAlchemyUserRepository) -> None:
        first = _make_user(role=Role.VIEWER)
        repo.save_new_user(first)

        second = _make_user(role=Role.ADMIN)
        persisted = repo.save_new_user(second)

        # An ADMIN inserted directly (e.g. by kingsec-bootstrap's own
        # UserRepository.save() path, exercised elsewhere) is not this
        # method's concern - what matters here is that save_new_user
        # itself never substitutes a different role than the one given,
        # for the first row or any other.
        assert persisted.role == Role.ADMIN
        stored = repo.find_by_id(second.id)
        assert stored is not None
        assert stored.role == Role.ADMIN

    def test_third_user_after_two_others_keeps_requested_role(self, repo: SqlAlchemyUserRepository) -> None:
        repo.save_new_user(_make_user(role=Role.VIEWER))
        repo.save_new_user(_make_user(role=Role.VIEWER))
        third = _make_user(role=Role.VIEWER)

        persisted = repo.save_new_user(third)

        assert persisted.role == Role.VIEWER
        assert repo.count() == 3
        assert repo.count_by_role(Role.ADMIN) == 0

    def test_concurrent_registrations_against_empty_table_each_keeps_its_own_role(
        self, repo: SqlAlchemyUserRepository
    ) -> None:
        """Phase 3 replacement for the old KSEC-73-05 race test: there is
        no shared "bootstrap slot" left to race over, so two concurrent
        inserts against a genuinely empty table should simply both
        succeed, each with its own given role, and the table must not
        end up corrupted (missing rows, duplicate ids, a role silently
        swapped) - proving the old race-for-a-special-slot behavior
        really is gone, not merely untested.
        """
        user_a = _make_user(role=Role.VIEWER)
        user_b = _make_user(role=Role.VIEWER)

        barrier = threading.Barrier(2)
        results: dict[str, Role] = {}
        errors: dict[str, BaseException] = {}

        def attempt(name: str, user: User) -> None:
            barrier.wait()  # force both threads to insert concurrently
            try:
                persisted = repo.save_new_user(user)
                results[name] = persisted.role
            except BaseException as exc:
                errors[name] = exc

        t1 = threading.Thread(target=attempt, args=("request-A", user_a))
        t2 = threading.Thread(target=attempt, args=("request-B", user_b))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert errors == {}, f"unexpected exception(s) during concurrent insert: {errors!r}"
        assert set(results.keys()) == {"request-A", "request-B"}
        assert list(results.values()) == [Role.VIEWER, Role.VIEWER], (
            f"expected both requests to keep VIEWER as given, got {results!r} - if either became "
            "ADMIN, the removed KSEC-73-05 bootstrap-claim behavior has reappeared"
        )

        # Both rows persisted correctly - no corruption, no lost writes.
        assert repo.count() == 2
        assert repo.count_by_role(Role.ADMIN) == 0
        assert repo.count_by_role(Role.VIEWER) == 2
