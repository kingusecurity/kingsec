from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.notification import Notification


class NotificationSenderPort(ABC):
    @abstractmethod
    def send(self, notification: Notification) -> str | None:
        """Deliver a notification. Returns error message on failure, None on success."""
        ...

    @abstractmethod
    def channel(self) -> str:
        """Return the channel name this sender handles."""
        ...
