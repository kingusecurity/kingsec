"""SQLAlchemy MFA secret repository."""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from kingsec.application.ports.outbound.mfa_secret_repository import MfaSecretRepository
from kingsec.domain.mfa import MfaSecret, MfaStatus
from kingsec.infrastructure.logging import get_logger
from kingsec.shared.errors import PersistenceError, log_exception

from .models import MfaSecretORM

_logger = get_logger("kingsec.infrastructure.persistence.mfa_secret")


class SqlAlchemyMfaSecretRepository(MfaSecretRepository):
    """SQLAlchemy-backed MFA secret store."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def find_by_user_id(self, user_id: str) -> MfaSecret | None:
        try:
            with self._session_factory() as session:
                stmt = select(MfaSecretORM).where(MfaSecretORM.user_id == user_id)
                orm = session.execute(stmt).scalar_one_or_none()
                if orm is None:
                    return None
                return MfaSecret(
                    user_id=orm.user_id,
                    secret_key=orm.secret_key,
                    status=MfaStatus(orm.status),
                )
        except SQLAlchemyError as exc:
            error = PersistenceError("failed to find MFA secret", context={"user_id": user_id}, cause=exc)
            log_exception(_logger, error)
            raise error from exc

    def save(self, secret: MfaSecret) -> None:
        try:
            with self._session_factory.begin() as session:
                stmt = select(MfaSecretORM).where(MfaSecretORM.user_id == secret.user_id)
                orm = session.execute(stmt).scalar_one_or_none()
                if orm is None:
                    orm = MfaSecretORM(
                        user_id=secret.user_id,
                        secret_key=secret.secret_key,
                        status=secret.status.value,
                        created_at=datetime.now(UTC).isoformat(),
                    )
                    session.add(orm)
                else:
                    orm.secret_key = secret.secret_key
                    orm.status = secret.status.value
            _logger.debug("MFA secret saved", user_id=secret.user_id)
        except SQLAlchemyError as exc:
            error = PersistenceError("failed to save MFA secret", context={"user_id": secret.user_id}, cause=exc)
            log_exception(_logger, error)
            raise error from exc

    def delete_by_user_id(self, user_id: str) -> None:
        try:
            with self._session_factory.begin() as session:
                stmt = select(MfaSecretORM).where(MfaSecretORM.user_id == user_id)
                orm = session.execute(stmt).scalar_one_or_none()
                if orm is not None:
                    session.delete(orm)
            _logger.debug("MFA secret deleted", user_id=user_id)
        except SQLAlchemyError as exc:
            error = PersistenceError("failed to delete MFA secret", context={"user_id": user_id}, cause=exc)
            log_exception(_logger, error)
            raise error from exc
