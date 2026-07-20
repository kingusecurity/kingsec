"""Notification domain model: channels, priorities, and notification entities."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class NotificationChannel(str, Enum):
    EMAIL = "email"
    WEBHOOK = "webhook"
    SLACK = "slack"
    DISCORD = "discord"
    MICROSOFT_TEAMS = "microsoft_teams"
    IN_APP = "in_app"


class NotificationStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    READ = "read"


class NotificationPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class NotificationId:
    value: str

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Notification:
    id: NotificationId
    user_id: str
    title: str
    message: str
    channel: NotificationChannel
    status: NotificationStatus
    priority: NotificationPriority
    event_type: str
    template_vars: dict[str, str]
    retry_count: int
    max_retries: int
    created_at: str
    updated_at: str
    read_at: str | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class NotificationPreference:
    user_id: str
    channel: NotificationChannel
    enabled: bool = True
    events: tuple[str, ...] = ()


@dataclass(frozen=True)
class NotificationTemplate:
    event_type: str
    channel: NotificationChannel
    subject_template: str
    body_template: str
    priority: NotificationPriority = NotificationPriority.MEDIUM
