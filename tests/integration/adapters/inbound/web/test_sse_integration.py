"""Integration test: SSE event streaming via HTTP endpoint.

Verifies the full SSE lifecycle:
  1. Connect to SSE endpoint
  2. Publish events on the bus
  3. Receive events in correct SSE format
  4. Verify event filtering by assessment_id
"""

from __future__ import annotations

import json
import threading
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.dependencies import get_application
from kingsec.adapters.inbound.web.sse import _get_event_publisher, router
from kingsec.application.events import AssessmentEvent, EVENT_ASSESSMENT_CREATED, EVENT_ASSESSMENT_COMPLETED
from kingsec.application.ports.outbound.event_publisher import EventPublisher
from kingsec.bootstrap.application import Application
from kingsec.infrastructure.events.in_memory_bus import InMemoryEventBus


class _StubApp:
    """Minimal Application stub that resolves ports from a dict."""

    def __init__(self, ports: dict[type, object]) -> None:
        self._ports = ports

    def resolve(self, service_type: type) -> object:
        return self._ports[service_type]


def _build_app(event_bus: InMemoryEventBus) -> FastAPI:
    """Build a FastAPI app with the given event bus."""
    app = FastAPI()
    app.state.kingsec_app = _StubApp({EventPublisher: event_bus})  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers

    register_error_handlers(app)
    app.include_router(router)
    app.dependency_overrides[_get_event_publisher] = lambda: event_bus

    return app


class TestSSEIntegration:
    """Full lifecycle: connect → publish → receive events."""

    def test_receives_events_in_real_time(self) -> None:
        """Events published on the bus appear in the SSE stream."""
        event_bus = InMemoryEventBus(maxsize=100)
        app = _build_app(event_bus)
        client = TestClient(app, raise_server_exceptions=False)

        event = AssessmentEvent(
            event_type=EVENT_ASSESSMENT_CREATED,
            assessment_id="asmt-int-001",
            state="authorized",
            message="Integration test event",
        )

        def publish_event() -> None:
            time.sleep(0.2)
            event_bus.publish(event)

        thread = threading.Thread(target=publish_event)
        thread.start()

        # Connect and read first event
        with client.stream("GET", "/api/v1/events") as response:
            # Read event type
            event_line = response.readline().decode("utf-8")
            assert event_line.startswith("event: assessment.created")

            # Read data
            data_line = response.readline().decode("utf-8")
            assert data_line.startswith("data: ")
            payload = json.loads(data_line[6:])
            assert payload["event_type"] == "assessment.created"
            assert payload["assessment_id"] == "asmt-int-001"
            assert payload["state"] == "authorized"
            assert payload["message"] == "Integration test event"

            thread.join(timeout=1.0)

    def test_multiple_subscribers_receive_same_events(self) -> None:
        """Multiple SSE connections receive the same events."""
        event_bus = InMemoryEventBus(maxsize=100)
        app = _build_app(event_bus)
        client = TestClient(app, raise_server_exceptions=False)

        event = AssessmentEvent(
            event_type=EVENT_ASSESSMENT_COMPLETED,
            assessment_id="asmt-int-002",
            state="completed",
            message="Completed",
        )

        received_by_subscriber1: list[str] = []
        received_by_subscriber2: list[str] = []

        def subscriber1() -> None:
            with client.stream("GET", "/api/v1/events") as response:
                for _ in range(2):  # event type + data
                    line = response.readline().decode("utf-8")
                    received_by_subscriber1.append(line)

        def subscriber2() -> None:
            with client.stream("GET", "/api/v1/events") as response:
                for _ in range(2):
                    line = response.readline().decode("utf-8")
                    received_by_subscriber2.append(line)

        def publish_event() -> None:
            time.sleep(0.3)
            event_bus.publish(event)

        # Start subscribers
        t1 = threading.Thread(target=subscriber1)
        t2 = threading.Thread(target=subscriber2)
        t1.start()
        t2.start()

        # Publish event
        t_pub = threading.Thread(target=publish_event)
        t_pub.start()

        # Wait for all threads
        t1.join(timeout=2.0)
        t2.join(timeout=2.0)
        t_pub.join(timeout=1.0)

        # Both subscribers should have received the event
        assert len(received_by_subscriber1) >= 1
        assert len(received_by_subscriber2) >= 1
        assert "assessment.completed" in received_by_subscriber1[0]
        assert "assessment.completed" in received_by_subscriber2[0]

    def test_filtering_by_assessment_id(self) -> None:
        """Events are filtered by assessment_id when specified."""
        event_bus = InMemoryEventBus(maxsize=100)
        app = _build_app(event_bus)
        client = TestClient(app, raise_server_exceptions=False)

        event1 = AssessmentEvent(
            event_type=EVENT_ASSESSMENT_CREATED,
            assessment_id="asmt-filter-001",
            state="authorized",
            message="Event 1",
        )
        event2 = AssessmentEvent(
            event_type=EVENT_ASSESSMENT_CREATED,
            assessment_id="asmt-filter-002",
            state="authorized",
            message="Event 2",
        )

        received_events: list[dict] = []

        def subscriber() -> None:
            with client.stream("GET", "/api/v1/events?assessment_id=asmt-filter-001") as response:
                # Read event type
                event_line = response.readline().decode("utf-8")
                # Read data
                data_line = response.readline().decode("utf-8")
                payload = json.loads(data_line[6:])
                received_events.append(payload)

        def publish_events() -> None:
            time.sleep(0.2)
            event_bus.publish(event1)
            event_bus.publish(event2)

        t_sub = threading.Thread(target=subscriber)
        t_pub = threading.Thread(target=publish_events)

        t_sub.start()
        t_pub.start()

        t_sub.join(timeout=2.0)
        t_pub.join(timeout=1.0)

        # Should only receive event1 (filtered by assessment_id)
        assert len(received_events) == 1
        assert received_events[0]["assessment_id"] == "asmt-filter-001"
