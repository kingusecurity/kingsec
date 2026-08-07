from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from kingsec.application.ports.outbound.lockout_repository import LockoutRepository
from kingsec.domain.rate_limit import AccountLockout
from kingsec.infrastructure.persistence.models import AccountLockoutORM


class SQLAlchemyLockoutRepository(LockoutRepository):
    """SQLAlchemy-backed account-lockout repository.

    Opens a fresh session per call and commits writes immediately —
    autocommit per call, matching the pattern used by every other
    repository in this codebase (e.g. SQLAlchemyNotificationRepository). A
    repository built around a single, long-lived, never-committed
    ``Session`` would hold SQLite's exclusive writer lock indefinitely and
    block every other write in the app.

    ``save`` upserts by ``user_id`` (the primary key) rather than always
    inserting: unlike a notification's UUID, a user's lockout record is
    the same row across every attempt for that account, and each call
    opens a fresh session with no identity map carried over from the
    previous one.
    """

    def __init__(self, session_factory: Callable[..., Session]) -> None:
        self._session_factory = session_factory

    def get(self, user_id: str) -> AccountLockout | None:
        with self._session_factory() as session:
            stmt = select(AccountLockoutORM).where(AccountLockoutORM.user_id == user_id)
            orm = session.execute(stmt).scalar_one_or_none()
            return _to_domain(orm) if orm else None

    def save(self, lockout: AccountLockout) -> None:
        with self._session_factory() as session:
            stmt = select(AccountLockoutORM).where(AccountLockoutORM.user_id == lockout.user_id)
            orm = session.execute(stmt).scalar_one_or_none()
            if orm is None:
                session.add(
                    AccountLockoutORM(
                        user_id=lockout.user_id,
                        locked_until=lockout.locked_until,
                        failed_attempts=lockout.failed_attempts,
                    )
                )
            else:
                orm.locked_until = lockout.locked_until
                orm.failed_attempts = lockout.failed_attempts
            session.commit()

    def delete(self, user_id: str) -> None:
        with self._session_factory() as session:
            stmt = select(AccountLockoutORM).where(AccountLockoutORM.user_id == user_id)
            orm = session.execute(stmt).scalar_one_or_none()
            if orm:
                session.delete(orm)
                session.commit()


def _to_domain(orm: AccountLockoutORM) -> AccountLockout:
    return AccountLockout(
        user_id=orm.user_id,
        locked_until=orm.locked_until,
        failed_attempts=orm.failed_attempts,
    )
