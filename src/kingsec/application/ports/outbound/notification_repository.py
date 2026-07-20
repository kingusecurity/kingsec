from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.notification import Notification, NotificationId, NotificationStatus


class NotificationRepositoryPort(ABC):
    @abstractmethod
    def save(self, notification: Notification) -> None:
        ...

    @abstractmethod
    def find_by_id(self, notification_id: NotificationId) -> Notification | None:
        ...

    @abstractmethod
    def find_by_user(self, user_id: str, limit: int = 50, offset: int = 0) -> tuple[list[Notification], int]:
        ...

    @abstractmethod
    def find_all(self, limit: int = 50, offset: int = 0) -> tuple[list[Notification], int]:
        ...

    @abstractmethod
    def update_status(self, notification_id: NotificationId, status: NotificationStatus, error_message: str | None = None) -> None:
        ...

    @abstractmethod
    def delete(self, notification_id: NotificationId) -> None:
        ...
