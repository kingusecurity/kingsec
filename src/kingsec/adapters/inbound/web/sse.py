"""Server-Sent Events (SSE) endpoint for live assessment progress.

This module provides a ``GET /api/v1/events`` endpoint that streams assessment
lifecycle events in real-time. Clients receive events as they happen:

- Assessment created
- Assessment started (running)
- Assessment completed
- Assessment failed
- Assessment cancelled
- Assessment deleted
- Report ready

The endpoint uses FastAPI's ``StreamingResponse`` with ``text/event-stream``
content type. Each event is formatted as:

    event: <event_type>
    data: <json_payload>
    id: <event_id>

Heartbeat comments are sent every 15 seconds to keep the connection alive.
On disconnect, the subscriber is automatically cleaned up.

Design decisions:
    * The SSE endpoint is read-only and stateless from the client's perspective.
    * Each SSE connection registers as a subscriber on the ``InMemoryEventBus``.
    * The bus is thread-safe, so publishing from background threads works.
    * Heartbeat prevents proxy/load-balancer timeouts.
    * The endpoint supports optional ``assessment_id`` query parameter filtering.
"""

from __future__ import annotations

import asyncio
import json
import logging
import queue
import uuid
from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, cast

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from kingsec.application.events import AssessmentEvent
from kingsec.application.ports.outbound.event_publisher import EventPublisher

from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application
    from kingsec.infrastructure.events.in_memory_bus import InMemoryEventBus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")

HEARTBEAT_INTERVAL = 15.0  # seconds


def _get_event_publisher(request: Request) -> EventPublisher:
    """Resolve the EventPublisher from the DI container."""
    app: Application = get_application(request)
    return cast(EventPublisher, app.resolve(EventPublisher))


def _format_sse(event: AssessmentEvent) -> str:
    """Format an AssessmentEvent as an SSE message."""
    payload = {
        "event_type": event.event_type,
        "assessment_id": event.assessment_id,
        "state": event.state,
        "message": event.message,
        "severity_counts": event.severity_counts,
        "timestamp": event.timestamp,
    }
    return f"event: {event.event_type}\ndata: {json.dumps(payload)}\nid: {uuid.uuid4().hex}\n\n"


async def _sse_generator(
    event_bus: InMemoryEventBus,
    assessment_id: str | None,
    client_id: str,
) -> AsyncGenerator[str, None]:
    """Generate SSE events from the event bus.

    Subscribes to the bus, yields formatted SSE messages, and sends
    heartbeat comments every 15 seconds. Automatically cleans up on disconnect.
    """
    subscriber = event_bus.subscribe(client_id)
    try:
        while True:
            try:
                event = await asyncio.wait_for(
                    asyncio.to_thread(subscriber.queue.get, timeout=1.0),
                    timeout=HEARTBEAT_INTERVAL,
                )
            except (TimeoutError, queue.Empty):
                yield ": heartbeat\n\n"
                continue

            if event is None:
                # Sentinel: bus shut down or subscriber removed
                break

            # Optional filter: only send events for a specific assessment
            if assessment_id and event.assessment_id != assessment_id:
                continue

            yield _format_sse(event)
    finally:
        event_bus.unsubscribe(client_id)


@router.get(
    "/events",
    tags=["events"],
    summary="Stream assessment events",
    description=(
        "Server-Sent Events endpoint for real-time assessment progress. "
        "Events include assessment lifecycle changes (created, running, completed, failed, cancelled, deleted) "
        "and report generation. Heartbeat comments are sent every 15 seconds."
    ),
)
async def stream_events(
    request: Request,
    assessment_id: str | None = Query(default=None, description="Filter by assessment ID"),
    event_bus: InMemoryEventBus = Depends(_get_event_publisher),
) -> StreamingResponse:
    """Stream assessment lifecycle events via Server-Sent Events.

    Connect to this endpoint to receive real-time updates about assessment
    state changes. Events are delivered as SSE messages with the following
    format:

        event: <event_type>
        data: {"event_type": "...", "assessment_id": "...", "state": "...", ...}

    Query parameters:
        assessment_id: Optional filter to only receive events for a specific assessment.

    Heartbeat comments are sent every 15 seconds to keep the connection alive.
    On client disconnect, the subscriber is automatically cleaned up.
    """
    client_id = f"sse-{uuid.uuid4().hex}"

    logger.info(
        "SSE client connected",
        extra={"client_id": client_id, "assessment_id": assessment_id},
    )

    async def cleanup_on_disconnect() -> None:
        """Clean up the subscriber when the client disconnects."""
        # This is called by FastAPI when the connection closes
        event_bus.unsubscribe(client_id)
        logger.info("SSE client disconnected", extra={"client_id": client_id})

    return StreamingResponse(
        _sse_generator(event_bus, assessment_id, client_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
        background=BackgroundTask(cleanup_on_disconnect),
    )
