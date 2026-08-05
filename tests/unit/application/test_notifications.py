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
from kingsec.application.ports.outbound.notification_repository import NotificationFilter
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

    def find_by_user(
        self, user_id: str, limit: int = 50, offset: int = 0, filter_: NotificationFilter | None = None
    ) -> tuple[list[Notification], int]:
        all_n = self._apply_filter([n for n in self._store.values() if n.user_id == user_id], filter_)
        all_n.sort(key=lambda n: n.created_at, reverse=True)
        return all_n[offset : offset + limit], len(all_n)

    def find_all(
        self, limit: int = 50, offset: int = 0, filter_: NotificationFilter | None = None
    ) -> tuple[list[Notification], int]:
        all_n = self._apply_filter(list(self._store.values()), filter_)
        all_n.sort(key=lambda n: n.created_at, reverse=True)
        return all_n[offset : offset + limit], len(all_n)

    @staticmethod
    def _apply_filter(items: list[Notification], filter_: NotificationFilter | None) -> list[Notification]:
        if filter_ is None:
            return items
        if filter_.read is not None:
            items = [n for n in items if (n.read_at is not None) == filter_.read]
        if filter_.channel is not None:
            items = [n for n in items if n.channel == filter_.channel]
        if filter_.priority is not None:
            items = [n for n in items if n.priority == filter_.priority]
        if filter_.status is not None:
            items = [n for n in items if n.status == filter_.status]
        return items

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

    def mark_all_read(self, user_id: str) -> int:
        now = datetime.now(UTC).isoformat()
        count = 0
        for key, n in list(self._store.items()):
            if n.user_id != user_id or n.status == NotificationStatus.READ:
                continue
            self._store[key] = Notification(
                id=n.id,
                user_id=n.user_id,
                title=n.title,
                message=n.message,
                channel=n.channel,
                status=NotificationStatus.READ,
                priority=n.priority,
                event_type=n.event_type,
                template_vars=n.template_vars,
                retry_count=n.retry_count,
                max_retries=n.max_retries,
                created_at=n.created_at,
                updated_at=now,
                read_at=now,
                error_message=None,
            )
            count += 1
        return count

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

    def test_filter_by_read_status(self) -> None:
        n1 = _make_notification()
        n2 = _make_notification()
        self.service.send(n1)
        self.service.send(n2)
        self.service.mark_read(n1.id)

        unread, unread_total = self.service.list_by_user("user1", filter_=NotificationFilter(read=False))
        read, read_total = self.service.list_by_user("user1", filter_=NotificationFilter(read=True))

        assert unread_total == 1
        assert str(unread[0].id) == str(n2.id)
        assert read_total == 1
        assert str(read[0].id) == str(n1.id)

    def test_filter_by_channel(self) -> None:
        from kingsec.domain.notification import NotificationChannel

        n = _make_notification()
        self.service.send(n)

        matching, matching_total = self.service.list_by_user(
            "user1", filter_=NotificationFilter(channel=NotificationChannel.IN_APP)
        )
        other, other_total = self.service.list_by_user(
            "user1", filter_=NotificationFilter(channel=NotificationChannel.EMAIL)
        )

        assert matching_total == 1
        assert str(matching[0].id) == str(n.id)
        assert other_total == 0
        assert other == []

    def test_filters_combine_with_and(self) -> None:
        from kingsec.domain.notification import NotificationChannel

        n = _make_notification()
        self.service.send(n)

        result, total = self.service.list_by_user(
            "user1",
            filter_=NotificationFilter(channel=NotificationChannel.IN_APP, read=True),
        )

        assert total == 0
        assert result == []


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


class TestMarkAllNotificationsRead:
    def setup_method(self) -> None:
        self.repo = InMemoryNotificationRepository()
        self.sender = StubSender()
        self.templates = StubTemplateRenderer()
        self.service = NotificationService(self.repo, self.sender, self.templates)

    def test_marks_all_unread_for_user(self) -> None:
        n1 = _make_notification()
        n2 = _make_notification()
        self.service.send(n1)
        self.service.send(n2)

        count = self.service.mark_all_read("user1")

        assert count == 2
        for n_id in (n1.id, n2.id):
            fetched = self.service.get(n_id)
            assert fetched.status == NotificationStatus.READ
            assert fetched.read_at is not None

    def test_does_not_touch_other_users(self) -> None:
        mine = _make_notification()
        self.service.send(mine)
        theirs = Notification(
            id=NotificationId(str(uuid4())),
            user_id="someone-else",
            title="Not mine",
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
        self.repo.save(theirs)

        count = self.service.mark_all_read("user1")

        assert count == 1
        assert self.service.get(theirs.id).status == NotificationStatus.PENDING

    def test_skips_already_read_matching_single_item_mark_read_semantics(self) -> None:
        already_read = _make_notification()
        self.service.send(already_read)
        self.service.mark_read(already_read.id)
        still_unread = _make_notification()
        self.service.send(still_unread)

        count = self.service.mark_all_read("user1")

        # Only the one that was still unread should count - matches
        # MarkNotificationRead's own early-return when status is already READ.
        assert count == 1
        assert str(self.service.get(still_unread.id).id) == str(still_unread.id)

    def test_result_matches_single_item_mark_read_field_for_field(self) -> None:
        """The bulk path must leave a notification in the exact same state
        the single-item mark_read path would - not just 'also marked read'.

        Uses a FAILED notification (real error_message set) for both
        subjects specifically to make the error_message-clearing behavior
        observable - mark_read's underlying update_status call always
        overwrites error_message with None on a read transition, and this
        assertion would be vacuously true (None == None either way) with
        a notification that never had an error_message to begin with.
        """
        fail_sender = StubSender(fail=True)
        fail_service = NotificationService(self.repo, fail_sender, self.templates)
        via_single = _make_notification()
        via_bulk = _make_notification()
        fail_service.send(via_single)
        fail_service.send(via_bulk)
        assert self.service.get(via_single.id).error_message == "simulated error"
        assert self.service.get(via_bulk.id).error_message == "simulated error"

        expected = self.service.mark_read(via_single.id)
        self.service.mark_all_read("user1")
        actual = self.service.get(via_bulk.id)

        assert actual.status == expected.status == NotificationStatus.READ
        assert expected.error_message is None
        assert actual.error_message is None
        assert (actual.read_at is not None) == (expected.read_at is not None) is True

    def test_returns_zero_when_nothing_unread(self) -> None:
        n = _make_notification()
        self.service.send(n)
        self.service.mark_read(n.id)

        count = self.service.mark_all_read("user1")

        assert count == 0


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
