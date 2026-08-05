from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from kingsec.domain.notification import (
    Notification,
    NotificationChannel,
    NotificationId,
    NotificationPriority,
    NotificationStatus,
)


@dataclass(frozen=True)
class NotificationFilter:
    read: bool | None = None
    channel: NotificationChannel | None = None
    priority: NotificationPriority | None = None
    status: NotificationStatus | None = None


class NotificationRepositoryPort(ABC):
    @abstractmethod
    def save(self, notification: Notification) -> None: ...

    @abstractmethod
    def find_by_id(self, notification_id: NotificationId) -> Notification | None: ...

    @abstractmethod
    def find_by_user(
        self, user_id: str, limit: int = 50, offset: int = 0, filter_: NotificationFilter | None = None
    ) -> tuple[list[Notification], int]: ...

    @abstractmethod
    def find_all(
        self, limit: int = 50, offset: int = 0, filter_: NotificationFilter | None = None
    ) -> tuple[list[Notification], int]: ...

    @abstractmethod
    def update_status(
        self, notification_id: NotificationId, status: NotificationStatus, error_message: str | None = None
    ) -> None: ...

    @abstractmethod
    def mark_all_read(self, user_id: str) -> int: ...

    @abstractmethod
    def delete(self, notification_id: NotificationId) -> None: ...
