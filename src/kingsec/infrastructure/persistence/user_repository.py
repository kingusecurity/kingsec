"""SQLAlchemy user repository — infrastructure implementation.

Implements the ``UserRepository`` port using SQLAlchemy and the existing
database session. Follows the same patterns as the assessment repository:
autocommit per call, shared engine.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC
from typing import Any

from sqlalchemy import exists, func, or_, select

from kingsec.application.ports import UserRepository
from kingsec.domain import Role, User
from kingsec.infrastructure.logging import get_logger

from .models import UserORM

_logger = get_logger("kingsec.infrastructure.persistence.user_repository")


class SqlAlchemyUserRepository(UserRepository):
    """SQLAlchemy-backed user repository."""

    def __init__(self, session_factory: Callable[..., Any]) -> None:
        self._session_factory = session_factory

    def find_by_username(self, username: str) -> User | None:
        with self._session_factory() as session:
            orm = session.execute(
                select(UserORM).where(func.lower(UserORM.username) == username.lower())
            ).scalar_one_or_none()
            return _to_domain(orm) if orm else None

    def find_by_id(self, user_id: str) -> User | None:
        with self._session_factory() as session:
            orm = session.get(UserORM, user_id)
            return _to_domain(orm) if orm else None

    def save(self, user: User) -> None:
        with self._session_factory() as session:
            existing = session.get(UserORM, user.id)
            if existing is not None:
                existing.username = user.username
                existing.email = user.email
                existing.password_hash = user.password_hash
                existing.role = user.role.name
                existing.is_active = user.is_active
                existing.created_at = user.created_at.isoformat()
                existing.last_login_at = user.last_login_at.isoformat() if user.last_login_at else None
            else:
                session.add(_to_orm(user))
            session.commit()

    def exists_by_username(self, username: str) -> bool:
        with self._session_factory() as session:
            return (
                session.execute(select(exists().where(func.lower(UserORM.username) == username.lower()))).scalar()
                or False
            )

    def exists_by_email(self, email: str) -> bool:
        with self._session_factory() as session:
            return session.execute(select(exists().where(func.lower(UserORM.email) == email.lower()))).scalar() or False

    def list_all(self, limit: int = 50, offset: int = 0) -> list[User]:
        with self._session_factory() as session:
            orms = (
                session.execute(select(UserORM).order_by(UserORM.username).limit(limit).offset(offset)).scalars().all()
            )
            return [_to_domain(o) for o in orms]

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
        with self._session_factory() as session:
            stmt = select(UserORM)
            count_stmt = select(func.count()).select_from(UserORM)
            filters = []
            if query:
                like = f"%{query}%"
                filters.append(or_(UserORM.username.ilike(like), UserORM.email.ilike(like)))
            if role:
                filters.append(UserORM.role == role.upper())
            if is_active is not None:
                filters.append(UserORM.is_active == is_active)
            if filters:
                stmt = stmt.where(*filters)
                count_stmt = count_stmt.where(*filters)
            order_col = getattr(UserORM, order_by, UserORM.username)
            order_fn = order_col.desc if order_dir == "desc" else order_col.asc
            stmt = stmt.order_by(order_fn()).offset(offset).limit(limit)
            orms = session.execute(stmt).scalars().all()
            total = session.execute(count_stmt).scalar() or 0
            return [_to_domain(o) for o in orms], total

    def count(self) -> int:
        with self._session_factory() as session:
            count = session.execute(select(func.count()).select_from(UserORM)).scalar()
            return count if count else 0

    def count_by_role(self, role: Role) -> int:
        with self._session_factory() as session:
            count = session.execute(select(func.count()).select_from(UserORM).where(UserORM.role == role.name)).scalar()
            return count if count else 0


def _to_domain(orm: UserORM) -> User:
    """Convert a UserORM row to a domain User entity."""
    from datetime import datetime

    return User(
        id=orm.id,
        username=orm.username,
        email=orm.email,
        password_hash=orm.password_hash,
        role=Role[orm.role],
        is_active=orm.is_active,
        created_at=datetime.fromisoformat(orm.created_at) if orm.created_at else datetime.now(UTC),
        last_login_at=datetime.fromisoformat(orm.last_login_at) if orm.last_login_at else None,
    )


def _to_orm(user: User) -> UserORM:
    """Convert a domain User entity to a UserORM row."""
    return UserORM(
        id=user.id,
        username=user.username,
        email=user.email,
        password_hash=user.password_hash,
        role=user.role.name,
        is_active=user.is_active,
        created_at=user.created_at.isoformat(),
        last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
    )
