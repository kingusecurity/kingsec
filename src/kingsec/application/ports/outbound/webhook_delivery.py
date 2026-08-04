"""Port for webhook delivery — application layer contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from kingsec.domain.integration import DeliveryRecord, WebhookEventType


class WebhookDeliveryPort(ABC):
    """Abstract port for delivering webhook notifications and reading their history."""

    @abstractmethod
    def deliver(self, event_type: WebhookEventType, payload: dict[str, Any]) -> list[DeliveryRecord]:
        """Deliver an event to every configured webhook target."""

    @abstractmethod
    def get_history(self, limit: int = 50) -> list[DeliveryRecord]:
        """Return the most recent delivery records, newest first."""
