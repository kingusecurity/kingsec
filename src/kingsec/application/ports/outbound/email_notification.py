"""Port for email notifications — application layer contract."""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.integration import DeliveryRecord


class EmailNotificationPort(ABC):
    """Abstract port for sending email notifications and reading their history."""

    @abstractmethod
    def send_raw(
        self,
        to_addresses: list[str],
        subject: str,
        html_body: str,
        plain_body: str | None = None,
    ) -> DeliveryRecord:
        """Send a pre-rendered email."""

    @abstractmethod
    def get_history(self, limit: int = 50) -> list[DeliveryRecord]:
        """Return the most recent delivery records, newest first."""
