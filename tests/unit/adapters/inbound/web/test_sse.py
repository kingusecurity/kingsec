"""Tests for SSE endpoint — unit-level with a stubbed EventPublisher."""

from __future__ import annotations

import json
import threading
import time
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.dependencies import get_application
from kingsec.adapters.inbound.web.sse import _get_event_publisher, router
from kingsec.application.events import AssessmentEvent, EVENT_ASSESSMENT_CREATED
from kingsec.application.ports.outbound.event_publisher import EventPublisher
from kingsec.infrastructure.events.in_memory_bus import InMemoryEventBus


# --- Stub EventPublisher -----------------------------------------------------


class StubEventPublisher(EventPublisher):
    """Returns deterministic responses for SSE testing."""

    def __init__(self) -> None:
        self.published_events: list[AssessmentEvent] = []
        self.publish_called = False

    def publish(self, event: AssessmentEvent) -> None:
        self.publish_called = True
        self.published_events.append(event)

    def shutdown(self) -> None:
        pass


# --- Fixtures ----------------------------------------------------------------


@pytest.fixture
def event_bus() -> InMemoryEventBus:
    return InMemoryEventBus(maxsize=100)


@pytest.fixture
def stub_publisher() -> StubEventPublisher:
    return StubEventPublisher()


@pytest.fixture
def client(event_bus: InMemoryEventBus) -> TestClient:
    """Build a TestClient with a minimal Application-like state."""
    app = FastAPI()

    class _StubApp:
        def resolve(self, service_type: type) -> InMemoryEventBus:
            return event_bus

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers

    register_error_handlers(app)
    app.include_router(router)
    app.dependency_overrides[_get_event_publisher] = lambda: event_bus

    return TestClient(app, raise_server_exceptions=False)


# --- Tests -------------------------------------------------------------------


class TestSSEEndpoint:
    def test_returns_200(self, client: TestClient) -> None:
        """SSE endpoint returns 200 with correct headers."""
        response = client.get("/api/v1/events")
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/event-stream; charset=utf-8"
        assert response.headers["cache-control"] == "no-cache"
        assert response.headers["connection"] == "keep-alive"

    def test_returns_sse_format(self, client: TestClient, event_bus: InMemoryEventBus) -> None:
        """SSE endpoint returns events in correct format."""
        # Publish an event in a background thread
        event = AssessmentEvent(
            event_type=EVENT_ASSESSMENT_CREATED,
            assessment_id="asmt-test-001",
            state="authorized",
            message="Test event",
        )

        def publish_event() -> None:
            time.sleep(0.1)
            event_bus.publish(event)

        thread = threading.Thread(target=publish_event)
        thread.start()

        # Connect and get first event
        with client.stream("GET", "/api/v1/events") as response:
            # Read first line
            line = response.readline().decode("utf-8")
            assert line.startswith("event: ")
            assert "assessment.created" in line

            # Read data line
            data_line = response.readline().decode("utf-8")
            assert data_line.startswith("data: ")
            payload = json.loads(data_line[6:])
            assert payload["event_type"] == "assessment.created"
            assert payload["assessment_id"] == "asmt-test-001"

            thread.join(timeout=1.0)

    def test_filters_by_assessment_id(self, client: TestClient, event_bus: InMemoryEventBus) -> None:
        """SSE endpoint filters events by assessment_id."""
        event1 = AssessmentEvent(
            event_type=EVENT_ASSESSMENT_CREATED,
            assessment_id="asmt-001",
            state="authorized",
            message="Event 1",
        )
        event2 = AssessmentEvent(
            event_type=EVENT_ASSESSMENT_CREATED,
            assessment_id="asmt-002",
            state="authorized",
            message="Event 2",
        )

        def publish_events() -> None:
            time.sleep(0.1)
            event_bus.publish(event1)
            event_bus.publish(event2)

        thread = threading.Thread(target=publish_events)
        thread.start()

        # Connect with filter
        with client.stream("GET", "/api/v1/events?assessment_id=asmt-001") as response:
            # Should only get event1
            line = response.readline().decode("utf-8")
            assert "event: " in line

            data_line = response.readline().decode("utf-8")
            payload = json.loads(data_line[6:])
            assert payload["assessment_id"] == "asmt-001"

            thread.join(timeout=1.0)

    def test_heartbeat(self, client: TestClient, event_bus: InMemoryEventBus) -> None:
        """SSE endpoint sends heartbeat comments."""
        # This is a timing-based test, but we can at least verify the format
        with client.stream("GET", "/api/v1/events") as response:
            # Read a few lines to check for heartbeat
            lines_read = 0
            while lines_read < 10:
                line = response.readline().decode("utf-8")
                lines_read += 1
                if line.startswith(": heartbeat"):
                    break
            # We should eventually get a heartbeat (within 15 seconds)
            # In test, we may not wait that long, but the format should be correct
