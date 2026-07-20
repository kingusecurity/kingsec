from __future__ import annotations

from kingsec.application.ports.notification_service import NotificationServicePort
from kingsec.application.ports.outbound import (
    AuditPublisher,
    NotificationRepositoryPort,
    NotificationSenderPort,
    TemplateRendererPort,
)
from kingsec.application.use_cases.notifications import (
    DeleteNotification,
    GetNotification,
    ListNotifications,
    MarkNotificationRead,
    RenderNotification,
    RetryFailedNotifications,
    SendBulkNotifications,
    SendNotification,
)
from kingsec.domain.notification import Notification, NotificationId


class NotificationService(NotificationServicePort):
    def __init__(
        self,
        repo: NotificationRepositoryPort,
        sender: NotificationSenderPort,
        templates: TemplateRendererPort,
        audit: AuditPublisher | None = None,
    ) -> None:
        self._send = SendNotification(repo, sender, templates, audit)
        self._send_bulk = SendBulkNotifications(self._send)
        self._list = ListNotifications(repo)
        self._get = GetNotification(repo)
        self._mark_read = MarkNotificationRead(repo, audit)
        self._delete = DeleteNotification(repo, audit)
        self._retry = RetryFailedNotifications(repo, sender, audit)
        self._render = RenderNotification(templates)

    def send(self, notification: Notification) -> Notification:
        return self._send.execute(
            user_id=notification.user_id,
            event_type=notification.event_type,
            channel=notification.channel,
            variables=notification.template_vars,
            priority=notification.priority,
            notification=notification,
        )

    def send_bulk(self, notifications: list[Notification]) -> list[Notification]:
        return self._send_bulk.execute(notifications)

    def list_by_user(self, user_id: str, limit: int = 50, offset: int = 0) -> tuple[list[Notification], int]:
        return self._list.execute(user_id=user_id, limit=limit, offset=offset)

    def list_all(self, limit: int = 50, offset: int = 0) -> tuple[list[Notification], int]:
        return self._list.execute(limit=limit, offset=offset)

    def get(self, notification_id: NotificationId) -> Notification:
        n = self._get.execute(notification_id)
        if n is None:
            from kingsec.application.errors import NotificationNotFoundError
            raise NotificationNotFoundError(f"Notification not found: {notification_id}")
        return n

    def mark_read(self, notification_id: NotificationId) -> Notification:
        n = self._mark_read.execute(notification_id)
        if n is None:
            from kingsec.application.errors import NotificationNotFoundError
            raise NotificationNotFoundError(f"Notification not found: {notification_id}")
        return n

    def delete(self, notification_id: NotificationId) -> None:
        self._delete.execute(notification_id)

    def retry_failed(self, notification_id: NotificationId) -> Notification:
        n = self._retry.execute(notification_id)
        if n is None:
            from kingsec.application.errors import NotificationNotFoundError
            raise NotificationNotFoundError(f"Notification not found: {notification_id}")
        return n

    def render(self, template: object, variables: dict[str, str]) -> tuple[str, str]:
        from kingsec.domain.notification import NotificationTemplate
        if not isinstance(template, NotificationTemplate):
            raise TypeError("template must be a NotificationTemplate")
        return self._render.execute(template.event_type, template.channel.value, variables)
