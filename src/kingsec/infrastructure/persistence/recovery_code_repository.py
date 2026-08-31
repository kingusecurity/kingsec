"""SQLAlchemy recovery code repository."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, cast

from sqlalchemy import CursorResult, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from kingsec.application.ports.outbound.recovery_code_repository import RecoveryCodeRepository
from kingsec.domain.mfa import MfaRecoveryCode, RecoveryCodeStatus
from kingsec.infrastructure.logging import get_logger
from kingsec.shared.errors import PersistenceError, log_exception

from .models import MfaRecoveryCodeORM

_logger = get_logger("kingsec.infrastructure.persistence.recovery_code")


class SqlAlchemyRecoveryCodeRepository(RecoveryCodeRepository):
    """SQLAlchemy-backed append-only recovery code store."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def find_by_user_id(self, user_id: str) -> Sequence[MfaRecoveryCode]:
        try:
            with self._session_factory() as session:
                stmt = select(MfaRecoveryCodeORM).where(MfaRecoveryCodeORM.user_id == user_id)
                orms = session.execute(stmt).scalars().all()
                return [MfaRecoveryCode(code_hash=o.code_hash, status=RecoveryCodeStatus(o.status)) for o in orms]
        except SQLAlchemyError as exc:
            error = PersistenceError("failed to find recovery codes", context={"user_id": user_id}, cause=exc)
            log_exception(_logger, error)
            raise error from exc

    def save_batch(self, user_id: str, codes: Sequence[MfaRecoveryCode]) -> None:
        try:
            with self._session_factory.begin() as session:
                old = (
                    session.execute(select(MfaRecoveryCodeORM).where(MfaRecoveryCodeORM.user_id == user_id))
                    .scalars()
                    .all()
                )
                for o in old:
                    session.delete(o)
                for code in codes:
                    orm = MfaRecoveryCodeORM(
                        user_id=user_id,
                        code_hash=code.code_hash,
                        status=code.status.value,
                    )
                    session.add(orm)
            _logger.debug("recovery codes saved", user_id=user_id)
        except SQLAlchemyError as exc:
            error = PersistenceError("failed to save recovery codes", context={"user_id": user_id}, cause=exc)
            log_exception(_logger, error)
            raise error from exc

    def mark_used(self, user_id: str, code_hash: str) -> bool:
        try:
            with self._session_factory.begin() as session:
                # KSEC-73-04: a single atomic conditional UPDATE, not a
                # separate SELECT-then-write - the WHERE clause requires
                # status still be ACTIVE, so of two concurrent callers
                # racing this exact statement for the same code, at most
                # one can ever match a row and transition it (the DB's
                # own row-level locking/serialization enforces this, not
                # anything in Python).
                stmt = (
                    update(MfaRecoveryCodeORM)
                    .where(
                        MfaRecoveryCodeORM.user_id == user_id,
                        MfaRecoveryCodeORM.code_hash == code_hash,
                        MfaRecoveryCodeORM.status == RecoveryCodeStatus.ACTIVE.value,
                    )
                    .values(status=RecoveryCodeStatus.USED.value)
                )
                result = cast("CursorResult[Any]", session.execute(stmt))
                transitioned = result.rowcount == 1
            _logger.debug("recovery code mark_used attempted", user_id=user_id, transitioned=transitioned)
            return transitioned
        except SQLAlchemyError as exc:
            error = PersistenceError("failed to mark recovery code used", context={"user_id": user_id}, cause=exc)
            log_exception(_logger, error)
            raise error from exc

    def delete_by_user_id(self, user_id: str) -> None:
        try:
            with self._session_factory.begin() as session:
                old = (
                    session.execute(select(MfaRecoveryCodeORM).where(MfaRecoveryCodeORM.user_id == user_id))
                    .scalars()
                    .all()
                )
                for o in old:
                    session.delete(o)
            _logger.debug("recovery codes deleted", user_id=user_id)
        except SQLAlchemyError as exc:
            error = PersistenceError("failed to delete recovery codes", context={"user_id": user_id}, cause=exc)
            log_exception(_logger, error)
            raise error from exc
