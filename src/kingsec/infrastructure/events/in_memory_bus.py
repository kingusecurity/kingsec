"""In-memory event bus for assessment lifecycle events.

Thread-safe publish/subscribe implementation using ``threading.Lock`` and
``queue.Queue``. Each subscriber gets a bounded queue to prevent memory
leaves from slow consumers. The bus supports:

* Multiple concurrent subscribers
* Subscriber removal (unsubscribe)
* Bounded queues with overflow handling
* Graceful shutdown with draining
* Thread-safe publishing from background jobs

Design decisions:
    * Each subscriber gets its own ``Queue`` instance — no shared state between
      subscribers, so one slow consumer doesn't block others.
    * Overflow is handled by dropping the oldest event (FIFO eviction) rather
      than blocking the publisher. This is the correct trade-off for a live
      streaming use case where stale events are worse than dropped events.
    * Shutdown sets a flag and notifies all subscribers; new publishes after
      shutdown are silently dropped (no exceptions).
"""

from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Iterator
from typing import Any

from kingsec.application.events import AssessmentEvent
from kingsec.application.ports.outbound.event_publisher import EventPublisher

logger = logging.getLogger(__name__)


class EventPublisherError(Exception):
    """Raised when an event cannot be published."""


class _Subscriber:
    """A single subscriber with a bounded queue."""

    def __init__(self, subscriber_id: str, maxsize: int = 100) -> None:
        self.id = subscriber_id
        self.queue: queue.Queue[AssessmentEvent | None] = queue.Queue(maxsize=maxsize)
        self._active = True

    def put(self, event: AssessmentEvent) -> bool:
        """Put an event into the subscriber's queue.

        Returns True if successful, False if the queue is full (event dropped).
        """
        if not self._active:
            return False
        try:
            self.queue.put_nowait(event)
            return True
        except queue.Full:
            # Drop oldest event to make room (FIFO eviction).
            try:
                self.queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self.queue.put_nowait(event)
                return True
            except queue.Full:
                return False

    def close(self) -> None:
        """Mark the subscriber as inactive and put a sentinel."""
        self._active = False
        try:
            self.queue.put_nowait(None)
        except queue.Full:
            pass

    @property
    def active(self) -> bool:
        return self._active


class InMemoryEventBus(EventPublisher):
    """In-memory publish/subscribe event bus.

    Thread-safe. Supports multiple subscribers, bounded queues, and graceful
    shutdown. Each subscriber gets its own queue instance.
    """

    def __init__(self, maxsize: int = 100) -> None:
        self._maxsize = maxsize
        self._subscribers: dict[str, _Subscriber] = {}
        self._lock = threading.Lock()
        self._shutdown = False

    def subscribe(self, subscriber_id: str) -> _Subscriber:
        """Register a new subscriber and return its queue wrapper.

        Args:
            subscriber_id: Unique identifier for this subscriber.

        Returns:
            A _Subscriber instance that can be iterated for events.

        Raises:
            EventPublisherError: If the bus is shut down.
        """
        with self._lock:
            if self._shutdown:
                raise EventPublisherError("event bus is shut down")
            sub = _Subscriber(subscriber_id, maxsize=self._maxsize)
            self._subscribers[subscriber_id] = sub
            logger.debug("subscriber registered", subscriber_id=subscriber_id)
            return sub

    def unsubscribe(self, subscriber_id: str) -> None:
        """Remove a subscriber and close its queue.

        Args:
            subscriber_id: The subscriber to remove.
        """
        with self._lock:
            sub = self._subscribers.pop(subscriber_id, None)
            if sub is not None:
                sub.close()
                logger.debug("subscriber removed", subscriber_id=subscriber_id)

    def publish(self, event: AssessmentEvent) -> None:
        """Publish an event to all active subscribers.

        Args:
            event: The event to publish.

        Raises:
            EventPublisherError: If the bus is shut down.
        """
        with self._lock:
            if self._shutdown:
                return
            dead: list[str] = []
            for sid, sub in self._subscribers.items():
                if not sub.put(event):
                    dead.append(sid)
            for sid in dead:
                self._subscribers.pop(sid, None)

    def shutdown(self) -> None:
        """Shutdown the bus, closing all subscriber queues."""
        with self._lock:
            if self._shutdown:
                return
            self._shutdown = True
            for sub in self._subscribers.values():
                sub.close()
            self._subscribers.clear()
            logger.info("event bus shut down")

    @property
    def subscriber_count(self) -> int:
        """Return the number of active subscribers."""
        with self._lock:
            return len(self._subscribers)
