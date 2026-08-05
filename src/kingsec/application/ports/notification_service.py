from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.application.ports.outbound.notification_repository import NotificationFilter
from kingsec.domain.notification import Notification, NotificationId


class NotificationServicePort(ABC):
    @abstractmethod
    def send(self, notification: Notification) -> Notification: ...

    @abstractmethod
    def send_bulk(self, notifications: list[Notification]) -> list[Notification]: ...

    @abstractmethod
    def list_by_user(
        self, user_id: str, limit: int = 50, offset: int = 0, filter_: NotificationFilter | None = None
    ) -> tuple[list[Notification], int]: ...

    @abstractmethod
    def list_all(
        self, limit: int = 50, offset: int = 0, filter_: NotificationFilter | None = None
    ) -> tuple[list[Notification], int]: ...

    @abstractmethod
    def get(self, notification_id: NotificationId) -> Notification: ...

    @abstractmethod
    def mark_read(self, notification_id: NotificationId) -> Notification: ...

    @abstractmethod
    def mark_all_read(self, user_id: str) -> int: ...

    @abstractmethod
    def delete(self, notification_id: NotificationId) -> None: ...

    @abstractmethod
    def retry_failed(self, notification_id: NotificationId) -> Notification: ...

    @abstractmethod
    def render(self, template: object, variables: dict[str, str]) -> tuple[str, str]: ...
