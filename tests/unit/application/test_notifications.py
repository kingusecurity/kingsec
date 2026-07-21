from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from kingsec.application.notification_service import NotificationService
from kingsec.application.ports.outbound import (
    NotificationRepositoryPort,
    NotificationSenderPort,
    TemplateRendererPort,
)
from kingsec.domain.notification import (
    Notification,
    NotificationChannel,
    NotificationId,
    NotificationPriority,
    NotificationStatus,
    NotificationTemplate,
)


class InMemoryNotificationRepository(NotificationRepositoryPort):
    def __init__(self) -> None:
        self._store: dict[str, Notification] = {}

    def save(self, notification: Notification) -> None:
        self._store[str(notification.id)] = notification

    def find_by_id(self, notification_id: NotificationId) -> Notification | None:
        return self._store.get(str(notification_id))

    def find_by_user(self, user_id: str, limit: int = 50, offset: int = 0) -> tuple[list[Notification], int]:
        all_n = [n for n in self._store.values() if n.user_id == user_id]
        all_n.sort(key=lambda n: n.created_at, reverse=True)
        return all_n[offset : offset + limit], len(all_n)

    def find_all(self, limit: int = 50, offset: int = 0) -> tuple[list[Notification], int]:
        all_n = list(self._store.values())
        all_n.sort(key=lambda n: n.created_at, reverse=True)
        return all_n[offset : offset + limit], len(all_n)

    def update_status(
        self, notification_id: NotificationId, status: NotificationStatus, error_message: str | None = None
    ) -> None:
        old = self._store.get(str(notification_id))
        if old is None:
            return
        n = Notification(
            id=old.id,
            user_id=old.user_id,
            title=old.title,
            message=old.message,
            channel=old.channel,
            status=status,
            priority=old.priority,
            event_type=old.event_type,
            template_vars=old.template_vars,
            retry_count=old.retry_count,
            max_retries=old.max_retries,
            created_at=old.created_at,
            updated_at=datetime.now(UTC).isoformat(),
            read_at=datetime.now(UTC).isoformat() if status == NotificationStatus.READ else old.read_at,
            error_message=error_message if status == NotificationStatus.FAILED else old.error_message,
        )
        self._store[str(notification_id)] = n

    def delete(self, notification_id: NotificationId) -> None:
        self._store.pop(str(notification_id), None)


class StubSender(NotificationSenderPort):
    def __init__(self, fail: bool = False) -> None:
        self._fail = fail
        self.sent: list[Notification] = []

    def send(self, notification: Notification) -> str | None:
        self.sent.append(notification)
        return "simulated error" if self._fail else None

    def channel(self) -> str:
        return NotificationChannel.IN_APP.value


class StubTemplateRenderer(TemplateRendererPort):
    def render(self, template: NotificationTemplate, variables: dict[str, str]) -> tuple[str, str]:
        return template.subject_template, template.body_template

    def get_template(self, event_type: str, channel: str) -> NotificationTemplate | None:
        return NotificationTemplate(
            event_type=event_type,
            channel=NotificationChannel(channel),
            subject_template=f"Subject: {event_type}",
            body_template=f"Body: {event_type}",
        )


def _make_notification() -> Notification:
    return Notification(
        id=NotificationId(str(uuid4())),
        user_id="user1",
        title="Test",
        message="Hello",
        channel=NotificationChannel.IN_APP,
        status=NotificationStatus.PENDING,
        priority=NotificationPriority.MEDIUM,
        event_type="test_event",
        template_vars={},
        retry_count=0,
        max_retries=3,
        created_at=datetime.now(UTC).isoformat(),
        updated_at=datetime.now(UTC).isoformat(),
    )


class TestSendNotification:
    def setup_method(self) -> None:
        self.repo = InMemoryNotificationRepository()
        self.sender = StubSender()
        self.templates = StubTemplateRenderer()
        self.service = NotificationService(self.repo, self.sender, self.templates)

    def test_send_creates_and_sends(self) -> None:
        n = _make_notification()
        result = self.service.send(n)
        assert result.status == NotificationStatus.SENT
        assert len(self.sender.sent) == 1

    def test_send_failure(self) -> None:
        self.sender._fail = True
        n = _make_notification()
        result = self.service.send(n)
        assert result.status == NotificationStatus.FAILED
        assert result.error_message == "simulated error"


class TestSendBulkNotifications:
    def setup_method(self) -> None:
        self.repo = InMemoryNotificationRepository()
        self.sender = StubSender()
        self.templates = StubTemplateRenderer()
        self.service = NotificationService(self.repo, self.sender, self.templates)

    def test_send_bulk(self) -> None:
        notifications = [_make_notification(), _make_notification()]
        results = self.service.send_bulk(notifications)
        assert len(results) == 2
        assert all(r.status == NotificationStatus.SENT for r in results)


class TestListNotifications:
    def setup_method(self) -> None:
        self.repo = InMemoryNotificationRepository()
        self.sender = StubSender()
        self.templates = StubTemplateRenderer()
        self.service = NotificationService(self.repo, self.sender, self.templates)

    def test_list_by_user(self) -> None:
        n = _make_notification()
        self.service.send(n)
        notifications, total = self.service.list_by_user("user1")
        assert total == 1
        assert len(notifications) == 1

    def test_list_by_user_empty(self) -> None:
        notifications, total = self.service.list_by_user("nonexistent")
        assert total == 0
        assert notifications == []

    def test_list_all(self) -> None:
        n = _make_notification()
        self.service.send(n)
        _notifications, total = self.service.list_all()
        assert total == 1


class TestGetNotification:
    def setup_method(self) -> None:
        self.repo = InMemoryNotificationRepository()
        self.sender = StubSender()
        self.templates = StubTemplateRenderer()
        self.service = NotificationService(self.repo, self.sender, self.templates)

    def test_get_existing(self) -> None:
        n = _make_notification()
        self.service.send(n)
        fetched = self.service.get(n.id)
        assert fetched is not None
        assert str(fetched.id) == str(n.id)

    def test_get_nonexistent_raises(self) -> None:
        import pytest

        from kingsec.application.errors import NotificationNotFoundError

        with pytest.raises(NotificationNotFoundError):
            self.service.get(NotificationId("no-such"))


class TestMarkNotificationRead:
    def setup_method(self) -> None:
        self.repo = InMemoryNotificationRepository()
        self.sender = StubSender()
        self.templates = StubTemplateRenderer()
        self.service = NotificationService(self.repo, self.sender, self.templates)

    def test_mark_read(self) -> None:
        n = _make_notification()
        self.service.send(n)
        result = self.service.mark_read(n.id)
        assert result.status == NotificationStatus.READ

    def test_mark_read_nonexistent_raises(self) -> None:
        import pytest

        from kingsec.application.errors import NotificationNotFoundError

        with pytest.raises(NotificationNotFoundError):
            self.service.mark_read(NotificationId("no-such"))


class TestDeleteNotification:
    def setup_method(self) -> None:
        self.repo = InMemoryNotificationRepository()
        self.sender = StubSender()
        self.templates = StubTemplateRenderer()
        self.service = NotificationService(self.repo, self.sender, self.templates)

    def test_delete(self) -> None:
        n = _make_notification()
        self.service.send(n)
        self.service.delete(n.id)
        from kingsec.application.errors import NotificationNotFoundError

        with pytest.raises(NotificationNotFoundError):
            self.service.get(n.id)


class TestRetryFailed:
    def setup_method(self) -> None:
        self.repo = InMemoryNotificationRepository()
        self.fail_sender = StubSender(fail=True)
        self.ok_sender = StubSender(fail=False)
        self.templates = StubTemplateRenderer()

    def test_retry_failed_succeeds(self) -> None:
        service = NotificationService(self.repo, self.fail_sender, self.templates)
        n = _make_notification()
        self.fail_sender._fail = True
        failed = service.send(n)
        assert failed.status == NotificationStatus.FAILED
        self.fail_sender._fail = False
        service2 = NotificationService(self.repo, self.ok_sender, self.templates)
        result = service2.retry_failed(n.id)
        assert result.status == NotificationStatus.SENT

    def test_retry_non_failed_returns_as_is(self) -> None:
        service = NotificationService(self.repo, self.ok_sender, self.templates)
        n = _make_notification()
        service.send(n)
        result = service.retry_failed(n.id)
        assert result.status == NotificationStatus.SENT
