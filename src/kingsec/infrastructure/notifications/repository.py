from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import CursorResult, Select, func, select
from sqlalchemy import update as sa_update
from sqlalchemy.orm import Session

from kingsec.application.ports.outbound import NotificationRepositoryPort
from kingsec.application.ports.outbound.notification_repository import NotificationFilter
from kingsec.domain.notification import (
    Notification,
    NotificationChannel,
    NotificationId,
    NotificationPriority,
    NotificationStatus,
)
from kingsec.infrastructure.notifications.orm import NotificationORM


class SQLAlchemyNotificationRepository(NotificationRepositoryPort):
    """SQLAlchemy-backed notification repository.

    Opens a fresh session per call and commits writes immediately —
    autocommit per call, matching the pattern used by every other
    repository in this codebase. A repository built around a single,
    long-lived, never-committed ``Session`` would hold SQLite's exclusive
    writer lock indefinitely and block every other write in the app.
    """

    def __init__(self, session_factory: Callable[..., Session]) -> None:
        self._session_factory = session_factory

    def save(self, notification: Notification) -> None:
        with self._session_factory() as session:
            orm = NotificationORM(
                id=str(notification.id),
                user_id=notification.user_id,
                title=notification.title,
                message=notification.message,
                channel=notification.channel.value,
                status=notification.status.value,
                priority=notification.priority.value,
                event_type=notification.event_type,
                template_vars=json.dumps(notification.template_vars),
                retry_count=notification.retry_count,
                max_retries=notification.max_retries,
                created_at=notification.created_at,
                updated_at=notification.updated_at,
                read_at=notification.read_at,
                error_message=notification.error_message,
            )
            session.add(orm)
            session.commit()

    def find_by_id(self, notification_id: NotificationId) -> Notification | None:
        with self._session_factory() as session:
            stmt = select(NotificationORM).where(NotificationORM.id == str(notification_id))
            orm = session.execute(stmt).scalar_one_or_none()
            return _to_domain(orm) if orm else None

    def find_by_user(
        self, user_id: str, limit: int = 50, offset: int = 0, filter_: NotificationFilter | None = None
    ) -> tuple[list[Notification], int]:
        with self._session_factory() as session:
            base = select(NotificationORM).where(NotificationORM.user_id == user_id)
            base = _apply_filter(base, filter_)
            count_stmt = select(func.count()).select_from(base.subquery())
            total = session.execute(count_stmt).scalar() or 0
            stmt = base.order_by(NotificationORM.created_at.desc()).offset(offset).limit(limit)
            orms: Sequence[NotificationORM] = session.execute(stmt).scalars().all()
            return [_to_domain(o) for o in orms], total

    def find_all(
        self, limit: int = 50, offset: int = 0, filter_: NotificationFilter | None = None
    ) -> tuple[list[Notification], int]:
        with self._session_factory() as session:
            base = _apply_filter(select(NotificationORM), filter_)
            count_stmt = select(func.count()).select_from(base.subquery())
            total = session.execute(count_stmt).scalar() or 0
            stmt = base.order_by(NotificationORM.created_at.desc()).offset(offset).limit(limit)
            orms: Sequence[NotificationORM] = session.execute(stmt).scalars().all()
            return [_to_domain(o) for o in orms], total

    def update_status(
        self, notification_id: NotificationId, status: NotificationStatus, error_message: str | None = None
    ) -> None:
        with self._session_factory() as session:
            stmt = select(NotificationORM).where(NotificationORM.id == str(notification_id))
            orm = session.execute(stmt).scalar_one_or_none()
            if orm is None:
                return
            orm.status = status.value
            orm.error_message = error_message
            if status == NotificationStatus.READ:
                orm.read_at = datetime.now(UTC).isoformat()
            session.commit()

    def mark_all_read(self, user_id: str) -> int:
        """Bulk version of update_status(..., NotificationStatus.READ).

        Must touch exactly the same fields, the same way, as the
        single-item path above: status -> read, read_at -> now,
        error_message -> None (update_status always overwrites
        error_message with whatever was passed, and mark_read never
        passes one) - and skip rows already in READ status, matching
        MarkNotificationRead's early-return-if-already-read check.
        """
        with self._session_factory() as session:
            now = datetime.now(UTC).isoformat()
            stmt = (
                sa_update(NotificationORM)
                .where(NotificationORM.user_id == user_id)
                .where(NotificationORM.status != NotificationStatus.READ.value)
                .values(status=NotificationStatus.READ.value, read_at=now, error_message=None)
            )
            result = cast("CursorResult[Any]", session.execute(stmt))
            session.commit()
            return int(result.rowcount) if result.rowcount is not None else 0

    def delete(self, notification_id: NotificationId) -> None:
        with self._session_factory() as session:
            stmt = select(NotificationORM).where(NotificationORM.id == str(notification_id))
            orm = session.execute(stmt).scalar_one_or_none()
            if orm:
                session.delete(orm)
                session.commit()


def _apply_filter(stmt: Select[tuple[NotificationORM]], filter_: NotificationFilter | None) -> Select[tuple[NotificationORM]]:
    if filter_ is None:
        return stmt
    if filter_.read is not None:
        stmt = stmt.where(NotificationORM.read_at.is_not(None) if filter_.read else NotificationORM.read_at.is_(None))
    if filter_.channel is not None:
        stmt = stmt.where(NotificationORM.channel == filter_.channel.value)
    if filter_.priority is not None:
        stmt = stmt.where(NotificationORM.priority == filter_.priority.value)
    if filter_.status is not None:
        stmt = stmt.where(NotificationORM.status == filter_.status.value)
    return stmt


def _to_domain(orm: NotificationORM) -> Notification:
    return Notification(
        id=NotificationId(orm.id),
        user_id=orm.user_id,
        title=orm.title,
        message=orm.message,
        channel=NotificationChannel(orm.channel),
        status=NotificationStatus(orm.status),
        priority=NotificationPriority(orm.priority),
        event_type=orm.event_type,
        template_vars=json.loads(orm.template_vars) if orm.template_vars else {},
        retry_count=orm.retry_count,
        max_retries=orm.max_retries,
        created_at=orm.created_at,
        updated_at=orm.updated_at,
        read_at=orm.read_at,
        error_message=orm.error_message,
    )
