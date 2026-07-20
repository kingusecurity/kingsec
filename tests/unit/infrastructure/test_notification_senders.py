from __future__ import annotations

from kingsec.domain.notification import (
    Notification,
    NotificationChannel,
    NotificationId,
    NotificationPriority,
    NotificationStatus,
)
from kingsec.infrastructure.notifications.senders import (
    DiscordSender,
    EmailSender,
    InAppSender,
    SlackSender,
    TeamsSender,
    WebhookSender,
)


def _make_notification(channel: NotificationChannel = NotificationChannel.IN_APP) -> Notification:
    return Notification(
        id=NotificationId("n1"),
        user_id="user1",
        title="Test",
        message="Hello",
        channel=channel,
        status=NotificationStatus.PENDING,
        priority=NotificationPriority.MEDIUM,
        event_type="test",
        template_vars={},
        retry_count=0,
        max_retries=3,
        created_at="now",
        updated_at="now",
    )


class TestEmailSender:
    def test_channel(self) -> None:
        assert EmailSender().channel() == "email"

    def test_send_no_config_returns_none(self) -> None:
        result = EmailSender().send(_make_notification(NotificationChannel.EMAIL))
        assert result is None


class TestWebhookSender:
    def test_channel(self) -> None:
        assert WebhookSender().channel() == "webhook"

    def test_send_no_endpoint_returns_error(self) -> None:
        result = WebhookSender().send(_make_notification(NotificationChannel.WEBHOOK))
        assert result == "Webhook endpoint not configured"


class TestSlackSender:
    def test_channel(self) -> None:
        assert SlackSender().channel() == "slack"

    def test_send_no_webhook_returns_error(self) -> None:
        result = SlackSender().send(_make_notification(NotificationChannel.SLACK))
        assert result == "Slack webhook not configured"


class TestDiscordSender:
    def test_channel(self) -> None:
        assert DiscordSender().channel() == "discord"

    def test_send_no_webhook_returns_error(self) -> None:
        result = DiscordSender().send(_make_notification(NotificationChannel.DISCORD))
        assert result == "Discord webhook not configured"


class TestTeamsSender:
    def test_channel(self) -> None:
        assert TeamsSender().channel() == "microsoft_teams"

    def test_send_no_webhook_returns_error(self) -> None:
        result = TeamsSender().send(_make_notification(NotificationChannel.MICROSOFT_TEAMS))
        assert result == "Teams webhook not configured"


class TestInAppSender:
    def test_channel(self) -> None:
        assert InAppSender().channel() == "in_app"

    def test_send_returns_none(self) -> None:
        result = InAppSender().send(_make_notification(NotificationChannel.IN_APP))
        assert result is None
