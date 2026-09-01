"""Tests for SSE endpoint — unit-level with a stubbed EventPublisher."""

from __future__ import annotations

import json

import anyio
import pytest
from fastapi import FastAPI
from httpx import AsyncBaseTransport, AsyncByteStream, AsyncClient, Request, Response

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
from kingsec.adapters.inbound.web.sse import _get_event_publisher, router
from kingsec.application.events import EVENT_ASSESSMENT_CREATED, AssessmentEvent
from kingsec.application.ports.outbound.event_publisher import EventPublisher
from kingsec.domain import Role
from kingsec.infrastructure.events.in_memory_bus import InMemoryEventBus


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


@pytest.fixture
def event_bus() -> InMemoryEventBus:
    return InMemoryEventBus(maxsize=100)


@pytest.fixture
def stub_publisher() -> StubEventPublisher:
    return StubEventPublisher()


@pytest.fixture
async def transport(event_bus: InMemoryEventBus) -> _StreamingTransport:
    """Build a streaming transport with an SSE-enabled FastAPI app."""
    app = FastAPI()

    class _StubApp:
        def resolve(self, service_type: type) -> InMemoryEventBus:
            return event_bus

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers

    register_error_handlers(app)
    app.include_router(router)
    app.dependency_overrides[_get_event_publisher] = lambda: event_bus
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        user_id="test-user",
        username="testuser",
        role=Role.VIEWER,
        claims=None,  # type: ignore[arg-type]
    )

    return _StreamingTransport(app, raise_app_exceptions=False)


# --- Streaming transport (same as integration tests) --------------------------


class _StreamingTransport(AsyncBaseTransport):
    """ASGI transport that delivers body chunks via anyio memory channel."""

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
    """AsyncByteStream that reads from an anyio memory channel."""

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


# --- Tests --------------------------------------------------------------------


class TestSSEEndpoint:
    @pytest.mark.anyio
    async def test_returns_200(self, transport: _StreamingTransport) -> None:
        """SSE endpoint returns 200 with correct headers."""
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            async with client.stream("GET", "/api/v1/events") as response:
                assert response.status_code == 200
                assert response.headers.get("content-type") == "text/event-stream; charset=utf-8"
                assert response.headers.get("cache-control") == "no-cache"
                assert response.headers.get("connection") == "keep-alive"
                # Cancel immediately — we only need headers
                await response.aclose()

    @pytest.mark.anyio
    async def test_returns_sse_format(self, transport: _StreamingTransport, event_bus: InMemoryEventBus) -> None:
        """SSE endpoint returns events in correct format."""
        event = AssessmentEvent(
            event_type=EVENT_ASSESSMENT_CREATED,
            assessment_id="asmt-test-001",
            state="authorized",
            message="Test event",
            owner_id="test-user",
        )

        async def publish_event() -> None:
            await anyio.sleep(0.1)
            event_bus.publish(event)

        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            async with client.stream("GET", "/api/v1/events") as response:
                async with anyio.create_task_group() as tg:
                    tg.start_soon(publish_event)

                    raw = b""
                    async for chunk in response.aiter_bytes():
                        raw += chunk
                        if b"data: " in raw:
                            break
                    tg.cancel_scope.cancel()

                lines = raw.decode("utf-8").splitlines()
                event_line = next((l for l in lines if l.startswith("event: ")), "")
                data_line = next((l for l in lines if l.startswith("data: ")), "")

                assert event_line == "event: assessment.created"
                payload = json.loads(data_line[6:])
                assert payload["event_type"] == "assessment.created"
                assert payload["assessment_id"] == "asmt-test-001"

    @pytest.mark.anyio
    async def test_filters_by_assessment_id(self, transport: _StreamingTransport, event_bus: InMemoryEventBus) -> None:
        """SSE endpoint filters events by assessment_id."""
        event1 = AssessmentEvent(
            event_type=EVENT_ASSESSMENT_CREATED,
            assessment_id="asmt-001",
            state="authorized",
            message="Event 1",
            owner_id="test-user",
        )
        event2 = AssessmentEvent(
            event_type=EVENT_ASSESSMENT_CREATED,
            assessment_id="asmt-002",
            state="authorized",
            message="Event 2",
            owner_id="test-user",
        )

        async def publish_events() -> None:
            await anyio.sleep(0.1)
            event_bus.publish(event1)
            event_bus.publish(event2)

        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            async with client.stream("GET", "/api/v1/events?assessment_id=asmt-001") as response:
                async with anyio.create_task_group() as tg:
                    tg.start_soon(publish_events)

                    raw = b""
                    async for chunk in response.aiter_bytes():
                        raw += chunk
                        if b"data: " in raw:
                            break
                    tg.cancel_scope.cancel()

                lines = raw.decode("utf-8").splitlines()
                data_line = next((l for l in lines if l.startswith("data: ")), "")
                payload = json.loads(data_line[6:])
                assert payload["assessment_id"] == "asmt-001"

    @pytest.mark.anyio
    async def test_heartbeat(self, transport: _StreamingTransport, event_bus: InMemoryEventBus) -> None:
        """SSE endpoint sends heartbeat comments."""
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            async with client.stream("GET", "/api/v1/events") as response:
                raw = b""
                async for chunk in response.aiter_bytes():
                    raw += chunk
                    if b": heartbeat" in raw:
                        break

                assert ": heartbeat" in raw.decode("utf-8")
