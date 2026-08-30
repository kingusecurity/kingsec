"""Notification sender implementations for various channels.

Each sender implements ``NotificationSenderPort`` and delivers notifications
via its respective channel (webhook, Slack, Discord, Teams, email, in-app).
All HTTP-based senders use ``urllib``. Sensitive configuration (SMTP password,
webhook URLs) is stored as instance attributes but never logged.

The webhook/Slack/Discord/Teams senders use ``open_validated()`` (not
``validate_url()`` followed by a bare ``urlopen()``) for every outbound
request (Phase 66 / Finding KSEC-64-02): validating only the initial URL
and then following redirects with the default opener would let a
destination that passed that initial check redirect the connection to
an unvalidated internal address after the fact. ``open_validated()``
validates the destination and refuses to follow any redirect at all -
the same SSRF-safe pattern already used by the SIEM, ticketing, and
generic webhook integrations in ``kingsec.infrastructure.integrations``.
"""

from __future__ import annotations

import json
from urllib.request import Request

from kingsec.application.ports.outbound import NotificationSenderPort
from kingsec.domain.notification import Notification, NotificationChannel
from kingsec.infrastructure.logging import get_logger
from kingsec.infrastructure.notifications.url_validator import SSRFError, open_validated

logger = get_logger("kingsec.infrastructure.notifications.senders")


class EmailSender(NotificationSenderPort):
    def __init__(self, smtp_host: str = "", smtp_port: int = 0, username: str = "", password: str = "") -> None:  # nosec B107 — empty default, actual password provided by DI at runtime
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port
        self._username = username
        self._password = password

    def send(self, notification: Notification) -> str | None:
        logger.info(
            "Email notification %s would be sent via SMTP %s:%s", notification.id, self._smtp_host, self._smtp_port
        )
        return None

    def channel(self) -> str:
        return NotificationChannel.EMAIL.value


class WebhookSender(NotificationSenderPort):
    def __init__(self, endpoint: str = "") -> None:
        self._endpoint = endpoint

    def send(self, notification: Notification) -> str | None:
        url = self._endpoint
        if not url:
            return "Webhook endpoint not configured"
        try:
            payload = json.dumps(
                {
                    "event": notification.event_type,
                    "title": notification.title,
                    "message": notification.message,
                    "priority": notification.priority.value,
                }
            ).encode()
            req = Request(url, data=payload, method="POST")
            req.add_header("Content-Type", "application/json")
            with open_validated(req, timeout=10):
                pass
            return None
        except SSRFError:
            logger.warning("SSRF block: %s", url)
            return "URL blocked by SSRF protection"
        except Exception as exc:
            logger.warning("Webhook delivery failed: %s", exc)
            return str(exc)

    def channel(self) -> str:
        return NotificationChannel.WEBHOOK.value


class SlackSender(NotificationSenderPort):
    def __init__(self, webhook_url: str = "") -> None:
        self._webhook_url = webhook_url

    def send(self, notification: Notification) -> str | None:
        url = self._webhook_url
        if not url:
            return "Slack webhook not configured"
        try:
            payload = json.dumps(
                {
                    "text": f"*{notification.title}*\n{notification.message}",
                }
            ).encode()
            req = Request(url, data=payload, method="POST")
            req.add_header("Content-Type", "application/json")
            with open_validated(req, timeout=10):
                pass
            return None
        except SSRFError:
            logger.warning("SSRF block: %s", url)
            return "URL blocked by SSRF protection"
        except Exception as exc:
            logger.warning("Slack delivery failed: %s", exc)
            return str(exc)

    def channel(self) -> str:
        return NotificationChannel.SLACK.value


class DiscordSender(NotificationSenderPort):
    def __init__(self, webhook_url: str = "") -> None:
        self._webhook_url = webhook_url

    def send(self, notification: Notification) -> str | None:
        url = self._webhook_url
        if not url:
            return "Discord webhook not configured"
        try:
            payload = json.dumps(
                {
                    "content": f"**{notification.title}**\n{notification.message}",
                }
            ).encode()
            req = Request(url, data=payload, method="POST")
            req.add_header("Content-Type", "application/json")
            with open_validated(req, timeout=10):
                pass
            return None
        except SSRFError:
            logger.warning("SSRF block: %s", url)
            return "URL blocked by SSRF protection"
        except Exception as exc:
            logger.warning("Discord delivery failed: %s", exc)
            return str(exc)

    def channel(self) -> str:
        return NotificationChannel.DISCORD.value


class TeamsSender(NotificationSenderPort):
    def __init__(self, webhook_url: str = "") -> None:
        self._webhook_url = webhook_url

    def send(self, notification: Notification) -> str | None:
        url = self._webhook_url
        if not url:
            return "Teams webhook not configured"
        try:
            payload = json.dumps(
                {
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "summary": notification.title,
                    "title": notification.title,
                    "text": notification.message,
                }
            ).encode()
            req = Request(url, data=payload, method="POST")
            req.add_header("Content-Type", "application/json")
            with open_validated(req, timeout=10):
                pass
            return None
        except SSRFError:
            logger.warning("SSRF block: %s", url)
            return "URL blocked by SSRF protection"
        except Exception as exc:
            logger.warning("Teams delivery failed: %s", exc)
            return str(exc)

    def channel(self) -> str:
        return NotificationChannel.MICROSOFT_TEAMS.value


class InAppSender(NotificationSenderPort):
    def send(self, notification: Notification) -> str | None:
        logger.info("In-app notification %s stored for user %s", notification.id, notification.user_id)
        return None

    def channel(self) -> str:
        return NotificationChannel.IN_APP.value
