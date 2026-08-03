"""Tests for rate limiting middleware."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.infrastructure.config.models import RateLimitSettings
from kingsec.infrastructure.middleware.rate_limit import RateLimitMiddleware, _TokenBucket


def _build_app(settings: RateLimitSettings | None = None) -> FastAPI:
    app = FastAPI()

    @app.get("/test")
    async def test_endpoint():
        return {"ok": True}

    @app.post("/api/v1/auth/register")
    async def register_endpoint():
        return {"ok": True}

    if settings is None:
        settings = RateLimitSettings()

    app.add_middleware(RateLimitMiddleware, settings=settings)
    return app


class TestTokenBucket:
    def test_consume_tokens(self) -> None:
        bucket = _TokenBucket(capacity=5, refill_rate=1.0)
        for _ in range(5):
            assert bucket.consume() is True
        assert bucket.consume() is False

    def test_refill_tokens(self) -> None:
        import time

        bucket = _TokenBucket(capacity=2, refill_rate=10.0)
        bucket.consume()
        bucket.consume()
        assert bucket.consume() is False
        time.sleep(0.3)
        assert bucket.consume() is True


class TestRateLimitMiddleware:
    def test_allows_requests_within_limit(self) -> None:
        settings = RateLimitSettings(enabled=True, api_requests_per_minute=10, burst_size=10)
        app = _build_app(settings)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/test")
        assert resp.status_code == 200
        assert "X-RateLimit-Limit" in resp.headers
        assert "X-RateLimit-Remaining" in resp.headers

    def test_blocks_requests_over_limit(self) -> None:
        settings = RateLimitSettings(enabled=True, api_requests_per_minute=1, burst_size=1)
        app = _build_app(settings)
        client = TestClient(app, raise_server_exceptions=False)
        client.get("/test")  # consume the token
        resp = client.get("/test")  # should be rate limited
        assert resp.status_code == 429
        assert resp.json()["error_code"] == "KS-RATE-001"
        assert "Retry-After" in resp.headers

    def test_disabled_rate_limiting(self) -> None:
        settings = RateLimitSettings(enabled=False)
        app = _build_app(settings)
        client = TestClient(app, raise_server_exceptions=False)
        for _ in range(10):
            resp = client.get("/test")
            assert resp.status_code == 200

    def test_auth_endpoints_have_separate_limit(self) -> None:
        settings = RateLimitSettings(
            enabled=True,
            api_requests_per_minute=100,
            auth_requests_per_minute=1,
            burst_size=1,
        )
        app = _build_app(settings)
        client = TestClient(app, raise_server_exceptions=False)
        client.post("/api/v1/auth/register")  # consume auth token
        resp = client.post("/api/v1/auth/register")  # should be rate limited
        assert resp.status_code == 429

    def test_rate_limit_headers_present(self) -> None:
        settings = RateLimitSettings(enabled=True, api_requests_per_minute=60, burst_size=30)
        app = _build_app(settings)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/test")
        assert "X-RateLimit-Limit" in resp.headers
        assert "X-RateLimit-Remaining" in resp.headers
        assert "X-RateLimit-Reset" in resp.headers
        assert resp.headers["X-RateLimit-Limit"] == "60"
