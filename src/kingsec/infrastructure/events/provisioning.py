"""DI wiring for the event bus infrastructure."""

from __future__ import annotations

from kingsec.application.ports.outbound.event_publisher import EventPublisher
from kingsec.bootstrap.container import Container

from .in_memory_bus import InMemoryEventBus


def register_events(container: Container, *, maxsize: int = 100) -> None:
    """Register the event bus and add a shutdown hook.

    Args:
        container: The DI container to register on.
        maxsize: Maximum queue size per subscriber.
    """

    bus = InMemoryEventBus(maxsize=maxsize)
    container.register_instance(EventPublisher, bus)
    container.add_shutdown_hook(lambda: bus.shutdown())
