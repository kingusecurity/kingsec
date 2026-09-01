"""Performance middleware: request timing, body size limits, response caching."""

from __future__ import annotations

import json
import time
from typing import Any

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import Message, Receive, Scope, Send

from kingsec.infrastructure.logging import get_logger

_logger = get_logger("kingsec.infrastructure.middleware.performance")


class RequestSizeLimitMiddleware:
    """Reject requests exceeding the configured body size limit.

    KSEC-86-03 (chunked request-body limit, Phase-84 carry-forward): the
    previous implementation (a ``BaseHTTPMiddleware`` checking only the
    ``Content-Length`` header) could be bypassed entirely by a client
    using ``Transfer-Encoding: chunked`` - chunked requests carry no
    ``Content-Length`` header at all (the two are mutually exclusive per
    HTTP/1.1), so the size check was simply never reached and an
    unbounded body would be passed straight through to the route handler.

    This is a plain ASGI middleware (not ``BaseHTTPMiddleware``) so it can
    enforce the limit while the body is still STREAMING in, chunk by
    chunk, exactly as the ASGI server delivers it - it never buffers the
    body itself merely to measure it (which would itself be a memory-
    exhaustion vector). The ``Content-Length`` header is still checked
    first as a fast, cheap rejection for the common case where the client
    supplies an honest one; the wrapped ``receive()`` is the real
    enforcement point and is what actually closes the chunked-encoding
    bypass, since it tracks the running total from the ASGI-level
    ``http.request`` messages regardless of what headers were sent.

    Once the limit is crossed, ``limited_receive()`` sends the 413
    response ITSELF and then hands the downstream app an
    ``http.disconnect`` message, rather than raising an exception and
    relying on it to propagate cleanly back up through ``self._app(...)``.
    That first approach was tried and rejected: this middleware sits
    underneath several ``BaseHTTPMiddleware``-based layers in the real
    app's stack (register_middleware() in bootstrap/web.py), and
    ``BaseHTTPMiddleware``'s own internal request/response bridging does
    not reliably let an exception raised deep inside a wrapped
    ``receive()`` call propagate back out to an enclosing plain-ASGI
    middleware's ``try/except`` - it was observed, end to end through the
    real middleware stack, to surface as an unhandled 500 instead of the
    intended 413. ``http.disconnect`` is the standard, framework-
    recognized ASGI signal for "the client is gone, stop processing" -
    Starlette's own body-reading treats it as a reason to stop silently
    rather than attempt to send its own response, so there is no
    double-send and no dependency on any particular set of enclosing
    middleware.
    """

    def __init__(self, app: Any, max_body_bytes: int = 10 * 1024 * 1024) -> None:
        self._app = app
        self._max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        content_length = next((v for k, v in scope.get("headers", []) if k == b"content-length"), None)
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                declared = None  # malformed header - let downstream request parsing reject it
            if declared is not None and declared > self._max_body_bytes:
                await self._send_413(send)
                return

        total = 0
        rejected = False

        async def limited_receive() -> Message:
            nonlocal total, rejected
            if rejected:
                # The downstream app already got told to stop (below); if
                # it calls receive() again anyway, keep telling it so -
                # never re-deliver body data past the point of rejection.
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self._max_body_bytes:
                    # Enforces the limit on a chunked (no Content-Length)
                    # body: each chunk is counted as it arrives, with
                    # nothing ever buffered beyond what the ASGI server
                    # already handed us one message at a time.
                    rejected = True
                    await self._send_413(send)
                    return {"type": "http.disconnect"}
            return message

        await self._app(scope, limited_receive, send)

    async def _send_413(self, send: Send) -> None:
        body = json.dumps({"detail": f"Request body too large (max {self._max_body_bytes} bytes)"}).encode()
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        })
        await send({"type": "http.response.body", "body": body})


class MetricsMiddleware(BaseHTTPMiddleware):
    """Record request latency and error status into PerformanceMetrics."""

    def __init__(self, app: Any, metrics: Any = None) -> None:
        super().__init__(app)
        self._metrics = metrics

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start = time.perf_counter()
        is_error = False
        try:
            response = await call_next(request)
            if response.status_code >= 400:
                is_error = True
        except Exception:
            is_error = True
            raise
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            if self._metrics is not None:
                self._metrics.record_request(elapsed_ms, is_error=is_error)
        return response


class ResponseCacheMiddleware(BaseHTTPMiddleware):
    """Simple in-memory response cache for GET requests.

    Only caches responses with 200 status and ``Cache-Control`` not set to
    ``no-cache``.  Respects ``If-None-Match`` for conditional requests.
    """

    def __init__(self, app: Any, default_ttl: int = 30, max_entries: int = 500) -> None:
        super().__init__(app)
        self._default_ttl = default_ttl
        self._max_entries = max_entries
        self._cache: dict[str, tuple[float, str, bytes]] = {}
        self._hits = 0
        self._misses = 0

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method != "GET":
            return await call_next(request)

        cache_key = f"{request.url.path}?{request.url.query}" if request.url.query else request.url.path

        import time as _time
        now = _time.monotonic()
        entry = self._cache.get(cache_key)
        if entry:
            expires, etag, body = entry
            if now < expires:
                if_none_match = request.headers.get("if-none-match")
                if if_none_match and if_none_match == etag:
                    self._hits += 1
                    return Response(status_code=304)
                self._hits += 1
                return Response(content=body, headers={"ETag": etag, "X-Cache": "HIT"})
            del self._cache[cache_key]

        self._misses += 1
        response = await call_next(request)

        if response.status_code == 200:
            try:
                body_bytes = b""
                body_iter = getattr(response, "body_iterator", None)
                if body_iter is not None:
                    async for chunk in body_iter:
                        if isinstance(chunk, str):
                            body_bytes += chunk.encode("utf-8")
                        else:
                            body_bytes += chunk
                else:
                    body_bytes = b""
                etag = f'"{hash(body_bytes) & 0xFFFFFFFF:08x}"'
                if len(self._cache) >= self._max_entries:
                    oldest = next(iter(self._cache))
                    del self._cache[oldest]
                self._cache[cache_key] = (now + self._default_ttl, etag, body_bytes)
                return Response(
                    content=body_bytes,
                    status_code=200,
                    headers={"ETag": etag, "X-Cache": "MISS"},
                )
            except Exception as exc:
                # Caching is a best-effort optimization: if anything above
                # fails, fall through to returning the original, uncached
                # response rather than breaking the request. Logged (not
                # silently swallowed) so a genuine bug in this path - e.g.
                # a body_iterator API change - stays visible instead of
                # permanently degrading to "never cached" with no trace.
                _logger.warning("response caching failed (best-effort): %s", exc)

        return response

    @property
    def hit_ratio(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    def clear(self) -> None:
        self._cache.clear()
        self._hits = 0
        self._misses = 0


def register_performance_middleware(
    app: FastAPI,
    metrics: Any = None,
    max_body_bytes: int = 10 * 1024 * 1024,
    cache_ttl: int = 30,
    cache_enabled: bool = True,
) -> None:
    """Register performance middleware on the FastAPI application."""
    app.add_middleware(RequestSizeLimitMiddleware, max_body_bytes=max_body_bytes)
    if metrics is not None:
        app.add_middleware(MetricsMiddleware, metrics=metrics)
    if cache_enabled:
        app.add_middleware(ResponseCacheMiddleware, default_ttl=cache_ttl)
