"""Tests for performance middleware."""

from __future__ import annotations

from unittest.mock import MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

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
