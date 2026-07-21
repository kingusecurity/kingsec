from __future__ import annotations

import json
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kingsec.application.ports.outbound import NotificationRepositoryPort
from kingsec.domain.notification import (
    Notification,
    NotificationChannel,
    NotificationId,
    NotificationPriority,
    NotificationStatus,
)
from kingsec.infrastructure.notifications.orm import NotificationORM


class SQLAlchemyNotificationRepository(NotificationRepositoryPort):
    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, notification: Notification) -> None:
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
        self._session.add(orm)

    def find_by_id(self, notification_id: NotificationId) -> Notification | None:
        stmt = select(NotificationORM).where(NotificationORM.id == str(notification_id))
        orm = self._session.execute(stmt).scalar_one_or_none()
        return _to_domain(orm) if orm else None

    def find_by_user(self, user_id: str, limit: int = 50, offset: int = 0) -> tuple[list[Notification], int]:
        count_stmt = select(func.count()).select_from(NotificationORM).where(NotificationORM.user_id == user_id)
        total = self._session.execute(count_stmt).scalar() or 0
        stmt = (
            select(NotificationORM)
            .where(NotificationORM.user_id == user_id)
            .order_by(NotificationORM.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        orms: Sequence[NotificationORM] = self._session.execute(stmt).scalars().all()
        return [_to_domain(o) for o in orms], total

    def find_all(self, limit: int = 50, offset: int = 0) -> tuple[list[Notification], int]:
        count_stmt = select(func.count()).select_from(NotificationORM)
        total = self._session.execute(count_stmt).scalar() or 0
        stmt = (
            select(NotificationORM)
            .order_by(NotificationORM.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        orms: Sequence[NotificationORM] = self._session.execute(stmt).scalars().all()
        return [_to_domain(o) for o in orms], total

    def update_status(self, notification_id: NotificationId, status: NotificationStatus, error_message: str | None = None) -> None:
        stmt = select(NotificationORM).where(NotificationORM.id == str(notification_id))
        orm = self._session.execute(stmt).scalar_one_or_none()
        if orm is None:
            return
        orm.status = status.value
        orm.error_message = error_message
        if status == NotificationStatus.READ:
            from datetime import UTC, datetime
            orm.read_at = datetime.now(UTC).isoformat()

    def delete(self, notification_id: NotificationId) -> None:
        stmt = select(NotificationORM).where(NotificationORM.id == str(notification_id))
        orm = self._session.execute(stmt).scalar_one_or_none()
        if orm:
            self._session.delete(orm)


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
