"""Integration test: SSE event streaming via HTTP endpoint.

Verifies the full SSE lifecycle:
  1. Connect to SSE endpoint
  2. Publish events on the bus
  3. Receive events in correct SSE format
  4. Verify event filtering by assessment_id

Uses anyio memory channels directly instead of Starlette's TestClient
because TestClient buffers the entire response before returning, which
is incompatible with infinite SSE streams. The anyio approach provides
true streaming: the ASGI app runs in a background task and delivers
body chunks through a memory channel as the SSE generator yields them.
"""

from __future__ import annotations

import json

import anyio
import pytest
from fastapi import FastAPI
from httpx import AsyncBaseTransport, AsyncByteStream, AsyncClient, Request, Response

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
from kingsec.adapters.inbound.web.sse import _get_event_publisher, router
from kingsec.application.events import (
    EVENT_ASSESSMENT_COMPLETED,
    EVENT_ASSESSMENT_CREATED,
    AssessmentEvent,
)
from kingsec.application.ports.outbound.event_publisher import EventPublisher
from kingsec.domain import Role
from kingsec.infrastructure.events.in_memory_bus import InMemoryEventBus


class _StubApp:
    """Minimal Application stub that resolves ports from a dict."""

    def __init__(self, ports: dict[type, object]) -> None:
        self._ports = ports

    def resolve(self, service_type: type) -> object:
        return self._ports[service_type]


def _build_app(event_bus: InMemoryEventBus, *, user_id: str = "test-user", role: Role = Role.VIEWER) -> FastAPI:
    """Build a FastAPI app with the given event bus."""
    app = FastAPI()
    app.state.kingsec_app = _StubApp({EventPublisher: event_bus})  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers

    register_error_handlers(app)
    app.include_router(router)
    app.dependency_overrides[_get_event_publisher] = lambda: event_bus
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        user_id=user_id,
        username=user_id,
        role=role,
        claims=None,  # type: ignore[arg-type]
    )

    return app


class _StreamingTransport(AsyncBaseTransport):
    """ASGI transport that delivers body chunks via anyio memory channel.

    Runs the ASGI app in a background ``asyncio.Task`` so the response
    can be returned as soon as headers are received. Body chunks are
    streamed through a memory channel, enabling true SSE streaming
    without blocking on ``response_complete``.
    """

    def __init__(
        self,
        app: object,
        *,
        raise_app_exceptions: bool = True,
        client: tuple[str, int] = ("127.0.0.1", 123),
    ) -> None:
        self.app = app
        self.raise_app_exceptions = raise_app_exceptions
        self.client = client

    async def handle_async_request(self, request: Request) -> Response:
        import asyncio

        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.4"},
            "http_version": "1.1",
            "method": request.method,
            "headers": [(k.lower(), v) for (k, v) in request.headers.raw],
            "scheme": request.url.scheme,
            "path": request.url.path,
            "raw_path": request.url.raw_path.split(b"?")[0],
            "query_string": request.url.query,
            "server": (request.url.host, request.url.port),
            "client": self.client,
            "root_path": "",
        }

        request_body_chunks = request.stream.__aiter__()
        request_complete = False

        status_code: int | None = None
        response_headers: list[tuple[bytes, bytes]] | None = None
        chunk_sender, chunk_receiver = anyio.create_memory_object_stream[bytes]()

        async def receive() -> dict:
            nonlocal request_complete
            if request_complete:
                await anyio.sleep_forever()
                return {"type": "http.disconnect"}
            try:
                body = await request_body_chunks.__anext__()
            except StopAsyncIteration:
                request_complete = True
                return {"type": "http.request", "body": b"", "more_body": False}
            return {"type": "http.request", "body": body, "more_body": True}

        async def send(message: dict) -> None:
            nonlocal status_code, response_headers
            if message["type"] == "http.response.start":
                status_code = message["status"]
                response_headers = message.get("headers", [])
            elif message["type"] == "http.response.body":
                body = message.get("body", b"")
                more_body = message.get("more_body", False)
                if body and request.method != "HEAD":
                    await chunk_sender.send(body)
                if not more_body:
                    await chunk_sender.aclose()

        async def run_app() -> None:
            try:
                await self.app(scope, receive, send)  # type: ignore[arg-type]
            except BaseException:
                if self.raise_app_exceptions:
                    raise
            finally:
                if not chunk_sender._closed:
                    await chunk_sender.aclose()

        loop = asyncio.get_running_loop()
        app_task = loop.create_task(run_app())

        try:
            while status_code is None:
                await anyio.sleep(0.001)

            stream = _ChannelStream(chunk_receiver, app_task)
            return Response(
                status_code=status_code,
                headers=list(response_headers or []),
                stream=stream,
            )
        except BaseException:
            app_task.cancel()
            raise


class _ChannelStream(AsyncByteStream):
    """AsyncByteStream that reads from an anyio memory channel.

    Cancels the background app task when the stream is exhausted or the
    channel is closed, ensuring proper cleanup.
    """

    def __init__(
        self,
        receive_stream: anyio.abc.ObjectReceiveStream[bytes],
        app_task: object,
    ) -> None:
        self._receive_stream = receive_stream
        self._app_task = app_task
        self._cleaned_up = False

    async def __aiter__(self) -> object:
        try:
            async for chunk in self._receive_stream:
                yield chunk
        except anyio.EndOfStream:
            pass
        finally:
            await self._cleanup()

    async def aclose(self) -> None:
        await self._cleanup()

    async def _cleanup(self) -> None:
        import asyncio

        if self._cleaned_up:
            return
        self._cleaned_up = True
        self._app_task.cancel()
        try:
            await self._app_task
        except (asyncio.CancelledError, BaseException):
            pass


class TestSSEIntegration:
    """Full lifecycle: connect -> publish -> receive events."""

    @pytest.mark.anyio
    async def test_receives_events_in_real_time(self) -> None:
        """Events published on the bus appear in the SSE stream."""
        event_bus = InMemoryEventBus(maxsize=100)
        app = _build_app(event_bus)

        transport = _StreamingTransport(app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            event = AssessmentEvent(
                event_type=EVENT_ASSESSMENT_CREATED,
                assessment_id="asmt-int-001",
                state="authorized",
                message="Integration test event",
                owner_id="test-user",
            )

            async def publish_event() -> None:
                await anyio.sleep(0.2)
                event_bus.publish(event)

            async with client.stream("GET", "/api/v1/events") as response:
                async with anyio.create_task_group() as tg:
                    tg.start_soon(publish_event)

                    raw = b""
                    async for chunk in response.aiter_bytes():
                        raw += chunk
                        if b"\ndata: " in raw or b"\nevent: " in raw:
                            break

                    lines = raw.decode("utf-8").splitlines()
                    event_line = next((l for l in lines if l.startswith("event: ")), "")
                    data_line = next((l for l in lines if l.startswith("data: ")), "")

                    assert event_line == "event: assessment.created"
                    payload = json.loads(data_line[6:])
                    assert payload["event_type"] == "assessment.created"
                    assert payload["assessment_id"] == "asmt-int-001"
                    assert payload["state"] == "authorized"
                    assert payload["message"] == "Integration test event"

                    tg.cancel_scope.cancel()

    @pytest.mark.anyio
    async def test_multiple_subscribers_receive_same_events(self) -> None:
        """Multiple SSE connections receive the same events."""
        event_bus = InMemoryEventBus(maxsize=100)
        app = _build_app(event_bus)
        transport = _StreamingTransport(app, raise_app_exceptions=False)

        received_by_sub1: list[str] = []
        received_by_sub2: list[str] = []

        async def subscriber(results: list[str]) -> None:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                async with client.stream("GET", "/api/v1/events") as response:
                    async for chunk in response.aiter_bytes():
                        text = chunk.decode("utf-8")
                        results.append(text)
                        if "assessment.completed" in text:
                            return

        async def publish_event() -> None:
            await anyio.sleep(0.3)
            event = AssessmentEvent(
                event_type=EVENT_ASSESSMENT_COMPLETED,
                assessment_id="asmt-int-002",
                state="completed",
                message="Completed",
                owner_id="test-user",
            )
            event_bus.publish(event)

        async with anyio.create_task_group() as tg:
            tg.start_soon(subscriber, received_by_sub1)
            tg.start_soon(subscriber, received_by_sub2)
            tg.start_soon(publish_event)

        assert len(received_by_sub1) >= 1
        assert len(received_by_sub2) >= 1
        assert "assessment.completed" in received_by_sub1[0]
        assert "assessment.completed" in received_by_sub2[0]

    @pytest.mark.anyio
    async def test_filtering_by_assessment_id(self) -> None:
        """Events are filtered by assessment_id when specified."""
        event_bus = InMemoryEventBus(maxsize=100)
        app = _build_app(event_bus)
        transport = _StreamingTransport(app, raise_app_exceptions=False)

        received_events: list[dict] = []

        async def subscriber() -> None:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                async with client.stream("GET", "/api/v1/events?assessment_id=asmt-filter-001") as response:
                    async for chunk in response.aiter_bytes():
                        text = chunk.decode("utf-8")
                        if "data: " in text:
                            data_part = text.split("data: ")[1].split("\n")[0]
                            received_events.append(json.loads(data_part))
                            return

        async def publish_events() -> None:
            await anyio.sleep(0.2)
            event1 = AssessmentEvent(
                event_type=EVENT_ASSESSMENT_CREATED,
                assessment_id="asmt-filter-001",
                state="authorized",
                message="Event 1",
                owner_id="test-user",
            )
            event2 = AssessmentEvent(
                event_type=EVENT_ASSESSMENT_CREATED,
                assessment_id="asmt-filter-002",
                state="authorized",
                message="Event 2",
                owner_id="test-user",
            )
            event_bus.publish(event1)
            event_bus.publish(event2)

        async with anyio.create_task_group() as tg:
            tg.start_soon(subscriber)
            tg.start_soon(publish_events)

        assert len(received_events) == 1
        assert received_events[0]["assessment_id"] == "asmt-filter-001"


class TestSSEOwnershipEnforcement:
    """KSEC-84-01: the event bus is a single global broadcast with no
    built-in per-subscriber partitioning - a non-owner, non-admin caller
    must never receive another user's assessment events, even though
    they're on the same shared bus."""

    @pytest.mark.anyio
    async def test_non_owner_receives_nothing_within_the_wait_window(self) -> None:
        event_bus = InMemoryEventBus(maxsize=100)
        app = _build_app(event_bus, user_id="bob", role=Role.VIEWER)
        transport = _StreamingTransport(app, raise_app_exceptions=False)

        received: list[str] = []

        async def subscriber() -> None:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                async with client.stream("GET", "/api/v1/events") as response:
                    async for chunk in response.aiter_bytes():
                        text = chunk.decode("utf-8")
                        if "\ndata: " in text or "\nevent: " in text:
                            received.append(text)
                            return

        async def publish_event() -> None:
            await anyio.sleep(0.2)
            event_bus.publish(
                AssessmentEvent(
                    event_type=EVENT_ASSESSMENT_CREATED,
                    assessment_id="asmt-alice-001",
                    state="authorized",
                    message="Alice's assessment - must not reach bob",
                    owner_id="alice",
                )
            )
            # Give the (incorrectly, if the bug regresses) delivered event a
            # moment to arrive before the timeout below fires either way.
            await anyio.sleep(0.5)

        with anyio.move_on_after(1.5):
            async with anyio.create_task_group() as tg:
                tg.start_soon(subscriber)
                tg.start_soon(publish_event)

        assert received == []

    @pytest.mark.anyio
    async def test_admin_receives_events_regardless_of_owner(self) -> None:
        event_bus = InMemoryEventBus(maxsize=100)
        app = _build_app(event_bus, user_id="admin-1", role=Role.ADMIN)
        transport = _StreamingTransport(app, raise_app_exceptions=False)

        received_events: list[dict] = []

        async def subscriber() -> None:
            async with AsyncClient(transport=transport, base_url="http://testserver") as client:
                async with client.stream("GET", "/api/v1/events") as response:
                    async for chunk in response.aiter_bytes():
                        text = chunk.decode("utf-8")
                        if "data: " in text:
                            data_part = text.split("data: ")[1].split("\n")[0]
                            received_events.append(json.loads(data_part))
                            return

        async def publish_event() -> None:
            await anyio.sleep(0.2)
            event_bus.publish(
                AssessmentEvent(
                    event_type=EVENT_ASSESSMENT_CREATED,
                    assessment_id="asmt-alice-002",
                    state="authorized",
                    message="Alice's assessment - admin CAN see it",
                    owner_id="alice",
                )
            )

        async with anyio.create_task_group() as tg:
            tg.start_soon(subscriber)
            tg.start_soon(publish_event)

        assert len(received_events) == 1
        assert received_events[0]["assessment_id"] == "asmt-alice-002"
