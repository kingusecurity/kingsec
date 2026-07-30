"""Performance middleware: request timing, body size limits, response caching."""

from __future__ import annotations

import time
from typing import Any

from fastapi import FastAPI, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests exceeding the configured body size limit."""

    def __init__(self, app: Any, max_body_bytes: int = 10 * 1024 * 1024) -> None:
        super().__init__(app)
        self._max_body_bytes = max_body_bytes

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self._max_body_bytes:
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={"detail": f"Request body too large (max {self._max_body_bytes} bytes)"},
            )
        return await call_next(request)


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
            except Exception:
                pass

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
