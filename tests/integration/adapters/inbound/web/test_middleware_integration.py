"""Integration test: middleware stack end-to-end.

Verifies that all middleware works together: security headers,
correlation ID, rate limiting, request logging.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.infrastructure.config.models import (
    CORSSettings,
    RateLimitSettings,
    SecurityHeadersSettings,
    MiddlewareSettings,
)
from kingsec.infrastructure.middleware import (
    CorrelationIDMiddleware,
    RateLimitMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
)


def _build_full_app() -> FastAPI:
    """Build a FastAPI app with all middleware enabled."""
    app = FastAPI()

    @app.get("/api/v1/health")
    async def health():
        return {"status": "ok"}

    @app.get("/api/v1/test")
    async def test_endpoint():
        return {"ok": True}

    app.add_middleware(RateLimitMiddleware, settings=RateLimitSettings(enabled=True, api_requests_per_minute=100, burst_size=50))
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(CorrelationIDMiddleware)
    app.add_middleware(SecurityHeadersMiddleware, settings=SecurityHeadersSettings())

    return app


class TestMiddlewareStackIntegration:
    def test_all_middleware_applied(self) -> None:
        app = _build_full_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/health")

        # Security headers
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"

        # Correlation ID
        assert "X-Request-ID" in resp.headers

        # Rate limiting
        assert "X-RateLimit-Limit" in resp.headers

        # Body
        assert resp.json()["status"] == "ok"

    def test_custom_correlation_id_forwarded(self) -> None:
        app = _build_full_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/api/v1/test",
            headers={"X-Request-ID": "my-trace-id-123"},
        )
        assert resp.headers["X-Request-ID"] == "my-trace-id-123"

    def test_rate_limiting_applied(self) -> None:
        settings = RateLimitSettings(enabled=True, api_requests_per_minute=2, burst_size=2)
        app = FastAPI()

        @app.get("/test")
        async def test_endpoint():
            return {"ok": True}

        app.add_middleware(RateLimitMiddleware, settings=settings)
        app.add_middleware(CorrelationIDMiddleware)
        app.add_middleware(SecurityHeadersMiddleware, settings=SecurityHeadersSettings())

        client = TestClient(app, raise_server_exceptions=False)
        client.get("/test")
        client.get("/test")
        resp = client.get("/test")
        assert resp.status_code == 429

    def test_security_headers_on_error_responses(self) -> None:
        app = FastAPI()

        @app.get("/error")
        async def error_endpoint():
            from fastapi import HTTPException
            raise HTTPException(status_code=500, detail="internal error")

        app.add_middleware(SecurityHeadersMiddleware, settings=SecurityHeadersSettings())

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/error")
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
