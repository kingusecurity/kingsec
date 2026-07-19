"""SQLAlchemy API key repository — infrastructure implementation."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select

from kingsec.application.ports import ApiKeyRepository
from kingsec.domain.api_key import ApiKey, ApiKeyScope, ApiKeyStatus
from kingsec.infrastructure.logging import get_logger

from .models import ApiKeyORM

_logger = get_logger("kingsec.infrastructure.persistence.api_key_repository")


class SqlAlchemyApiKeyRepository(ApiKeyRepository):
    """SQLAlchemy-backed API key repository."""

    def __init__(self, session_factory: callable) -> None:
        self._session_factory = session_factory

    def find_by_id(self, api_key_id: str) -> ApiKey | None:
        with self._session_factory() as session:
            orm = session.get(ApiKeyORM, api_key_id)
            return _to_domain(orm) if orm else None

    def find_by_user_id(self, user_id: str, limit: int = 50, offset: int = 0) -> list[ApiKey]:
        with self._session_factory() as session:
            orms = (
                session.execute(
                    select(ApiKeyORM)
                    .where(ApiKeyORM.user_id == user_id)
                    .order_by(ApiKeyORM.created_at.desc())
                    .limit(limit)
                    .offset(offset)
                )
                .scalars()
                .all()
            )
            return [_to_domain(o) for o in orms]

    def save(self, key: ApiKey) -> None:
        with self._session_factory() as session:
            existing = session.get(ApiKeyORM, key.id)
            if existing is not None:
                existing.name = key.name
                existing.key_hash = key.key_hash
                existing.scope = key.scope.value
                existing.status = key.status.value
                existing.last_used_at = (
                    key.last_used_at.isoformat() if key.last_used_at else None
                )
            else:
                session.add(_to_orm(key))
            session.commit()

    def delete(self, api_key_id: str) -> None:
        with self._session_factory() as session:
            orm = session.get(ApiKeyORM, api_key_id)
            if orm is not None:
                session.delete(orm)
                session.commit()

    def count_by_user(self, user_id: str) -> int:
        with self._session_factory() as session:
            count = session.execute(
                select(func.count())
                .select_from(ApiKeyORM)
                .where(ApiKeyORM.user_id == user_id)
            ).scalar()
            return count if count else 0


def _to_domain(orm: ApiKeyORM) -> ApiKey:
    return ApiKey(
        id=orm.id,
        user_id=orm.user_id,
        name=orm.name,
        key_hash=orm.key_hash,
        scope=ApiKeyScope(orm.scope),
        status=ApiKeyStatus(orm.status),
        last_used_at=datetime.fromisoformat(orm.last_used_at) if orm.last_used_at else None,
        created_at=datetime.fromisoformat(orm.created_at) if orm.created_at else datetime.now(),
    )


def _to_orm(key: ApiKey) -> ApiKeyORM:
    return ApiKeyORM(
        id=key.id,
        user_id=key.user_id,
        name=key.name,
        key_hash=key.key_hash,
        scope=key.scope.value,
        status=key.status.value,
        last_used_at=key.last_used_at.isoformat() if key.last_used_at else None,
        created_at=key.created_at.isoformat(),
    )
