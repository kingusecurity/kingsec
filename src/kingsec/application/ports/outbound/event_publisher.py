"""Outbound port: event publisher for lifecycle notifications.

The application layer defines *what* events are published. The infrastructure
decides *how* they are delivered (in-memory bus, message queue, WebSocket, etc.).
This port is the seam between business logic and delivery strategy.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.application.events import AssessmentEvent


class EventPublisher(ABC):
    """Publishes assessment lifecycle events to subscribers."""

    @abstractmethod
    def publish(self, event: AssessmentEvent) -> None:
        """Publish an event to all current subscribers.

        Args:
            event: The event to publish.

        Raises:
            EventPublisherError: If the event cannot be published.
        """
        ...

    @abstractmethod
    def shutdown(self) -> None:
        """Shutdown the publisher, cleaning up resources.

        Must be idempotent and safe to call from a shutdown hook.
        """
        ...
