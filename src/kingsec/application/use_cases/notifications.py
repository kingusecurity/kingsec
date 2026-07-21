from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from kingsec.application.ports.outbound import (
    AuditPublisher,
    NotificationRepositoryPort,
    NotificationSenderPort,
    TemplateRendererPort,
)
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.notification import (
    Notification,
    NotificationChannel,
    NotificationId,
    NotificationPriority,
    NotificationStatus,
    NotificationTemplate,
)


class SendNotification:
    def __init__(
        self,
        repo: NotificationRepositoryPort,
        sender: NotificationSenderPort,
        templates: TemplateRendererPort,
        audit: AuditPublisher | None = None,
    ) -> None:
        self._repo = repo
        self._sender = sender
        self._templates = templates
        self._audit = audit

    def execute(
        self,
        user_id: str,
        event_type: str,
        channel: NotificationChannel,
        variables: dict[str, str] | None = None,
        priority: NotificationPriority | None = None,
        notification: Notification | None = None,
    ) -> Notification:
        if notification is not None:
            pass
        else:
            template = self._templates.get_template(event_type, channel.value)
            if template is None:
                template = self._default_template(event_type, channel)
            priority = priority or template.priority
            subject, body = self._templates.render(template, variables or {})
            now = datetime.now(UTC).isoformat()
            notification = Notification(
                id=NotificationId(str(uuid4())),
                user_id=user_id,
                title=subject,
                message=body,
                channel=channel,
                status=NotificationStatus.PENDING,
                priority=priority,
                event_type=event_type,
                template_vars=variables or {},
                retry_count=0,
                max_retries=3,
                created_at=now,
                updated_at=now,
            )
        self._repo.save(notification)
        error = self._sender.send(notification)
        if error:
            notification = _with_status(notification, NotificationStatus.FAILED, error)
            self._repo.update_status(notification.id, NotificationStatus.FAILED, error)
            self._publish_audit(AuditAction.NOTIFICATION_FAILED, notification, error)
        else:
            notification = _with_status(notification, NotificationStatus.SENT)
            self._repo.update_status(notification.id, NotificationStatus.SENT)
            self._publish_audit(AuditAction.NOTIFICATION_SENT, notification)
        return notification

    def _publish_audit(self, action: AuditAction, notification: Notification, error: str | None = None) -> None:
        if self._audit is None:
            return
        self._audit.record(
            AuditEntry(
                action=action,
                resource_type="notification",
                resource_id=str(notification.id),
                success=error is None,
                reason=error or "",
                metadata={
                    "user_id": notification.user_id,
                    "channel": notification.channel.value,
                    "event_type": notification.event_type,
                },
            )
        )

    @staticmethod
    def _default_template(event_type: str, channel: NotificationChannel) -> NotificationTemplate:
        return NotificationTemplate(
            event_type=event_type,
            channel=channel,
            subject_template=f"Notification: {event_type}",
            body_template=f"Event: {event_type}\n\n{{message}}",
        )


class SendBulkNotifications:
    def __init__(self, send: SendNotification) -> None:
        self._send = send

    def execute(
        self,
        items: list[Notification],
    ) -> list[Notification]:
        return [
            self._send.execute(
                user_id=n.user_id,
                event_type=n.event_type,
                channel=n.channel,
                variables=n.template_vars,
                priority=n.priority,
                notification=n,
            )
            for n in items
        ]


class ListNotifications:
    def __init__(self, repo: NotificationRepositoryPort) -> None:
        self._repo = repo

    def execute(self, user_id: str | None = None, limit: int = 50, offset: int = 0) -> tuple[list[Notification], int]:
        if user_id:
            return self._repo.find_by_user(user_id, limit, offset)
        return self._repo.find_all(limit, offset)


class GetNotification:
    def __init__(self, repo: NotificationRepositoryPort) -> None:
        self._repo = repo

    def execute(self, notification_id: NotificationId) -> Notification | None:
        return self._repo.find_by_id(notification_id)


class MarkNotificationRead:
    def __init__(self, repo: NotificationRepositoryPort, audit: AuditPublisher | None = None) -> None:
        self._repo = repo
        self._audit = audit

    def execute(self, notification_id: NotificationId) -> Notification | None:
        notification = self._repo.find_by_id(notification_id)
        if notification is None or notification.status == NotificationStatus.READ:
            return notification
        self._repo.update_status(notification_id, NotificationStatus.READ)
        if self._audit:
            self._audit.record(
                AuditEntry(
                    action=AuditAction.NOTIFICATION_READ,
                    resource_type="notification",
                    resource_id=str(notification_id),
                    success=True,
                )
            )
        datetime.now(UTC).isoformat()
        return _with_status(notification, NotificationStatus.READ)


class DeleteNotification:
    def __init__(self, repo: NotificationRepositoryPort, audit: AuditPublisher | None = None) -> None:
        self._repo = repo
        self._audit = audit

    def execute(self, notification_id: NotificationId) -> bool:
        notification = self._repo.find_by_id(notification_id)
        if notification is None:
            return False
        self._repo.delete(notification_id)
        if self._audit:
            self._audit.record(
                AuditEntry(
                    action=AuditAction.NOTIFICATION_DELETED,
                    resource_type="notification",
                    resource_id=str(notification_id),
                    success=True,
                )
            )
        return True


class RetryFailedNotifications:
    def __init__(
        self,
        repo: NotificationRepositoryPort,
        sender: NotificationSenderPort,
        audit: AuditPublisher | None = None,
    ) -> None:
        self._repo = repo
        self._sender = sender
        self._audit = audit

    def execute(self, notification_id: NotificationId) -> Notification | None:
        notification = self._repo.find_by_id(notification_id)
        if notification is None or notification.status != NotificationStatus.FAILED:
            return notification
        if notification.retry_count >= notification.max_retries:
            return notification
        datetime.now(UTC).isoformat()
        notification.retry_count + 1
        error = self._sender.send(notification)
        if error:
            notification = _with_status(notification, NotificationStatus.FAILED, error)
            self._repo.update_status(notification_id, NotificationStatus.FAILED, error)
            self._publish_audit(self._audit, AuditAction.NOTIFICATION_FAILED, notification, error)
        else:
            notification = _with_status(notification, NotificationStatus.SENT)
            self._repo.update_status(notification_id, NotificationStatus.SENT)
            self._publish_audit(self._audit, AuditAction.NOTIFICATION_RETRIED, notification)
        return notification

    @staticmethod
    def _publish_audit(audit: AuditPublisher | None, action: AuditAction, notification: Notification, error: str | None = None) -> None:
        if audit is None:
            return
        audit.record(
            AuditEntry(
                action=action,
                resource_type="notification",
                resource_id=str(notification.id),
                success=error is None,
                reason=error or "",
            )
        )


class RenderNotification:
    def __init__(self, templates: TemplateRendererPort) -> None:
        self._templates = templates

    def execute(self, event_type: str, channel: str, variables: dict[str, str]) -> tuple[str, str]:
        template = self._templates.get_template(event_type, channel)
        if template is None:
            template = NotificationTemplate(
                event_type=event_type,
                channel=NotificationChannel(channel),
                subject_template=f"Notification: {event_type}",
                body_template=f"Event: {event_type}",
            )
        return self._templates.render(template, variables)


def _with_status(
    notification: Notification,
    status: NotificationStatus,
    error_message: str | None = None,
) -> Notification:
    now = datetime.now(UTC).isoformat()
    return Notification(
        id=notification.id,
        user_id=notification.user_id,
        title=notification.title,
        message=notification.message,
        channel=notification.channel,
        status=status,
        priority=notification.priority,
        event_type=notification.event_type,
        template_vars=notification.template_vars,
        retry_count=notification.retry_count,
        max_retries=notification.max_retries,
        created_at=notification.created_at,
        updated_at=now,
        read_at=now if status == NotificationStatus.READ else notification.read_at,
        error_message=error_message,
    )
