from __future__ import annotations

from kingsec.domain.notification import (
    Notification,
    NotificationChannel,
    NotificationId,
    NotificationPriority,
    NotificationStatus,
)


class TestNotificationId:
    def test_str(self) -> None:
        nid = NotificationId("abc-123")
        assert str(nid) == "abc-123"


class TestNotificationChannel:
    def test_values(self) -> None:
        assert NotificationChannel.EMAIL.value == "email"
        assert NotificationChannel.WEBHOOK.value == "webhook"
        assert NotificationChannel.SLACK.value == "slack"
        assert NotificationChannel.DISCORD.value == "discord"
        assert NotificationChannel.MICROSOFT_TEAMS.value == "microsoft_teams"
        assert NotificationChannel.IN_APP.value == "in_app"


class TestNotificationStatus:
    def test_values(self) -> None:
        assert NotificationStatus.PENDING.value == "pending"
        assert NotificationStatus.SENT.value == "sent"
        assert NotificationStatus.FAILED.value == "failed"
        assert NotificationStatus.READ.value == "read"


class TestNotificationPriority:
    def test_values(self) -> None:
        assert NotificationPriority.LOW.value == "low"
        assert NotificationPriority.MEDIUM.value == "medium"
        assert NotificationPriority.HIGH.value == "high"
        assert NotificationPriority.CRITICAL.value == "critical"


class TestNotification:
    def test_create(self) -> None:
        n = Notification(
            id=NotificationId("n1"),
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
            created_at="2025-01-01T00:00:00Z",
            updated_at="2025-01-01T00:00:00Z",
        )
        assert str(n.id) == "n1"
        assert n.user_id == "user1"
        assert n.title == "Test"
        assert n.channel == NotificationChannel.IN_APP
        assert n.status == NotificationStatus.PENDING

    def test_immutable(self) -> None:
        n = Notification(
            id=NotificationId("n1"),
            user_id="u1",
            title="T",
            message="M",
            channel=NotificationChannel.EMAIL,
            status=NotificationStatus.PENDING,
            priority=NotificationPriority.LOW,
            event_type="e",
            template_vars={},
            retry_count=0,
            max_retries=3,
            created_at="now",
            updated_at="now",
        )
        import pytest

        with pytest.raises(AttributeError):
            n.title = "changed"
