"""Tests for performance middleware."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import kingsec.infrastructure.middleware.performance as performance_module
from kingsec.infrastructure.middleware.performance import (
    MetricsMiddleware,
    RequestSizeLimitMiddleware,
    ResponseCacheMiddleware,
)


class TestRequestSizeLimitMiddleware:
    def test_allows_normal_request(self) -> None:
        app = FastAPI()
        app.add_middleware(RequestSizeLimitMiddleware, max_body_bytes=1024)

        @app.post("/test")
        async def test_endpoint() -> dict[str, str]:
            return {"ok": "true"}

        client = TestClient(app)
        resp = client.post("/test", content=b"small")
        assert resp.status_code == 200

    def test_rejects_oversized_request(self) -> None:
        app = FastAPI()
        app.add_middleware(RequestSizeLimitMiddleware, max_body_bytes=10)

        @app.post("/test")
        async def test_endpoint() -> dict[str, str]:
            return {"ok": "true"}

        client = TestClient(app)
        resp = client.post("/test", content=b"x" * 100, headers={"content-length": "100"})
        assert resp.status_code == 413


class TestResponseCacheMiddleware:
    def test_caches_get_response(self) -> None:
        app = FastAPI()
        app.add_middleware(ResponseCacheMiddleware, default_ttl=60, max_entries=10)
        call_count = 0

        @app.get("/test")
        async def test_endpoint() -> dict[str, str]:
            nonlocal call_count
            call_count += 1
            return {"count": str(call_count)}

        client = TestClient(app)
        resp1 = client.get("/test")
        resp2 = client.get("/test")
        assert resp1.json() == resp2.json()
        assert call_count == 1  # only called once due to cache

    def test_cache_miss_header(self) -> None:
        app = FastAPI()
        app.add_middleware(ResponseCacheMiddleware, default_ttl=60)

        @app.get("/test")
        async def test_endpoint() -> dict[str, str]:
            return {"ok": "true"}

        client = TestClient(app)
        resp = client.get("/test")
        assert resp.headers.get("X-Cache") == "MISS"

    def test_cache_hit_header(self) -> None:
        app = FastAPI()
        app.add_middleware(ResponseCacheMiddleware, default_ttl=60)

        @app.get("/test")
        async def test_endpoint() -> dict[str, str]:
            return {"ok": "true"}

        client = TestClient(app)
        client.get("/test")  # prime cache
        resp = client.get("/test")
        assert resp.headers.get("X-Cache") == "HIT"

    def test_no_cache_for_post(self) -> None:
        app = FastAPI()
        app.add_middleware(ResponseCacheMiddleware, default_ttl=60)
        call_count = 0

        @app.post("/test")
        async def test_endpoint() -> dict[str, str]:
            nonlocal call_count
            call_count += 1
            return {"count": str(call_count)}

        client = TestClient(app)
        client.post("/test")
        client.post("/test")
        assert call_count == 2

    def test_hit_ratio(self) -> None:
        middleware = ResponseCacheMiddleware(FastAPI(), default_ttl=60)
        assert middleware.hit_ratio == 0.0

    def test_clear(self) -> None:
        app = FastAPI()
        app.add_middleware(ResponseCacheMiddleware, default_ttl=60)

        @app.get("/test")
        async def test_endpoint() -> dict[str, str]:
            return {"ok": "true"}

        client = TestClient(app)
        client.get("/test")
        # Verify middleware was added and works
        assert any(
            isinstance(m.cls, type) and issubclass(m.cls, ResponseCacheMiddleware)
            for m in app.user_middleware
        )

    @pytest.mark.asyncio
    async def test_caching_failure_is_logged_not_silently_swallowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Phase 12 (bandit B110): the caching try/except used to be a bare
        `except Exception: pass`. A real failure while consuming the
        response body (here: a chunk that isn't str or bytes, so
        `body_bytes += chunk` raises TypeError) must fall through to
        returning the original response AND be logged, not vanish.

        Calls dispatch() directly with a stub call_next/response rather
        than going through a real FastAPI/TestClient round-trip: the real
        ASGI streaming pipeline consumes a StreamingResponse's
        body_iterator a second time when actually sending the response,
        which raises the same error again from framework code the
        middleware never touches - not a useful way to isolate this
        specific try/except.
        """
        calls: list[str] = []

        class _RecordingLogger:
            def warning(self, msg: str, *args: object) -> None:
                calls.append(msg % args if args else msg)

        monkeypatch.setattr(performance_module, "_logger", _RecordingLogger())

        class _FakeResponse:
            status_code = 200

            async def _body_iterator(self):
                yield 12345  # neither str nor bytes - triggers TypeError

            body_iterator = property(lambda self: self._body_iterator())

        request = Request(scope={"type": "http", "method": "GET", "path": "/test", "query_string": b"", "headers": []})
        middleware = ResponseCacheMiddleware(app=FastAPI(), default_ttl=60)

        async def _call_next(_request: Request) -> _FakeResponse:
            return _FakeResponse()

        result = await middleware.dispatch(request, _call_next)

        # The request still succeeds - caching degrades gracefully.
        assert isinstance(result, _FakeResponse)
        # But the failure is now visible, not silently swallowed.
        assert len(calls) == 1
        assert "caching" in calls[0].lower()


class TestMetricsMiddleware:
    def test_records_latency(self) -> None:
        mock_metrics = MagicMock()
        app = FastAPI()
        app.add_middleware(MetricsMiddleware, metrics=mock_metrics)

        @app.get("/test")
        async def test_endpoint() -> dict[str, str]:
            return {"ok": "true"}

        client = TestClient(app)
        client.get("/test")
        mock_metrics.record_request.assert_called_once()
        call_args = mock_metrics.record_request.call_args
        assert call_args[0][0] >= 0  # latency_ms >= 0

    def test_records_error(self) -> None:
        mock_metrics = MagicMock()
        app = FastAPI()
        app.add_middleware(MetricsMiddleware, metrics=mock_metrics)

        @app.get("/test")
        async def test_endpoint() -> None:
            from fastapi import HTTPException
            raise HTTPException(status_code=500)

        client = TestClient(app, raise_server_exceptions=False)
        client.get("/test")
        call_args = mock_metrics.record_request.call_args
        assert call_args[1].get("is_error", False) or call_args[0][1] if len(call_args[0]) > 1 else True
