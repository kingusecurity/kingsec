"""Integration tests for SQLAlchemyLockoutRepository.

Exercises every LockoutRepository method against a real SQLite database -
including the one behavior this repository specifically has to get right
that a fresh-insert-only repository wouldn't: saving the SAME user_id
across multiple calls (simulating repeated failed-login attempts) must
update the existing row, not raise a duplicate-primary-key error.
"""

from __future__ import annotations

from kingsec.domain.rate_limit import AccountLockout
from kingsec.infrastructure.rate_limit.sql_lockout_repository import (
    SQLAlchemyLockoutRepository,
)


def test_get_returns_none_when_no_record_exists(session_factory) -> None:
    repo = SQLAlchemyLockoutRepository(session_factory)
    assert repo.get("no-such-user") is None


def test_save_then_get_round_trips(session_factory) -> None:
    repo = SQLAlchemyLockoutRepository(session_factory)
    repo.save(AccountLockout(user_id="u1", locked_until=2000.0, failed_attempts=3))

    fetched = repo.get("u1")

    assert fetched is not None
    assert fetched.user_id == "u1"
    assert fetched.locked_until == 2000.0
    assert fetched.failed_attempts == 3


def test_save_updates_existing_row_instead_of_inserting_a_duplicate(session_factory) -> None:
    """The real scenario this repository must handle: repeated failed
    attempts for the same account call save() multiple times with the
    same user_id, each from a fresh session with no identity map carried
    over. Must upsert, not raise an IntegrityError on the second call."""
    repo = SQLAlchemyLockoutRepository(session_factory)

    repo.save(AccountLockout(user_id="u1", locked_until=0.0, failed_attempts=1))
    repo.save(AccountLockout(user_id="u1", locked_until=0.0, failed_attempts=2))
    repo.save(AccountLockout(user_id="u1", locked_until=1900.0, failed_attempts=3))

    fetched = repo.get("u1")
    assert fetched is not None
    assert fetched.failed_attempts == 3
    assert fetched.locked_until == 1900.0


def test_save_is_isolated_per_user(session_factory) -> None:
    repo = SQLAlchemyLockoutRepository(session_factory)
    repo.save(AccountLockout(user_id="u1", locked_until=0.0, failed_attempts=1))
    repo.save(AccountLockout(user_id="u2", locked_until=1900.0, failed_attempts=5))

    assert repo.get("u1").failed_attempts == 1  # type: ignore[union-attr]
    assert repo.get("u2").failed_attempts == 5  # type: ignore[union-attr]


def test_delete_removes_the_record(session_factory) -> None:
    repo = SQLAlchemyLockoutRepository(session_factory)
    repo.save(AccountLockout(user_id="u1", locked_until=1900.0, failed_attempts=5))

    repo.delete("u1")

    assert repo.get("u1") is None


def test_delete_nonexistent_user_does_not_raise(session_factory) -> None:
    repo = SQLAlchemyLockoutRepository(session_factory)
    repo.delete("no-such-user")  # must not raise


def test_persists_across_a_new_repository_instance(session_factory) -> None:
    """The actual point of this whole task: a lockout written by one
    repository instance (simulating one request) must be readable by a
    completely separate instance (simulating a later request, or a
    process restart) as long as they share the same underlying database."""
    writer = SQLAlchemyLockoutRepository(session_factory)
    writer.save(AccountLockout(user_id="u1", locked_until=1900.0, failed_attempts=5))

    reader = SQLAlchemyLockoutRepository(session_factory)
    fetched = reader.get("u1")

    assert fetched is not None
    assert fetched.locked_until == 1900.0
    assert fetched.failed_attempts == 5
