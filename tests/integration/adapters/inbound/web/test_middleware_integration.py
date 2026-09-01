"""Integration test: middleware stack end-to-end.

Verifies that all middleware works together: security headers,
correlation ID, rate limiting, request logging.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from kingsec.infrastructure.config.models import (
    RateLimitSettings,
    SecurityHeadersSettings,
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

    app.add_middleware(
        RateLimitMiddleware, settings=RateLimitSettings(enabled=True, api_requests_per_minute=100, burst_size=50)
    )
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


class TestRequestSizeLimitIsWiredIntoTheRealApp:
    """KSEC-84-01: RequestSizeLimitMiddleware existed and was tested in
    isolation, but register_middleware() (the ONE function the real app
    factory calls to assemble its middleware stack) never added it - every
    endpoint, including pre-auth ones, buffered an unbounded request body
    before any route-level check could run. This test goes through the
    REAL register_middleware(), not a hand-built middleware stack, so a
    future regression (someone removing the registration line) is caught
    here rather than only in RequestSizeLimitMiddleware's own isolated
    unit test."""

    def _build_app_via_real_registration(self, max_request_body_bytes: int) -> FastAPI:
        from kingsec.bootstrap.web import register_middleware
        from kingsec.infrastructure.config import Settings

        app = FastAPI()

        @app.post("/api/v1/test")
        async def echo(request: Request) -> dict[str, int]:
            body = await request.body()
            return {"received_bytes": len(body)}

        settings = Settings()
        settings = settings.model_copy(
            update={"middleware": settings.middleware.model_copy(update={"max_request_body_bytes": max_request_body_bytes})}
        )
        register_middleware(app, settings)
        return app

    def test_oversized_request_is_rejected_before_reaching_the_route(self) -> None:
        app = self._build_app_via_real_registration(max_request_body_bytes=100)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/test", content=b"x" * 1000)
        assert resp.status_code == 413

    def test_request_within_the_limit_reaches_the_route(self) -> None:
        app = self._build_app_via_real_registration(max_request_body_bytes=1_000_000)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/test", content=b"x" * 100)
        assert resp.status_code == 200
        assert resp.json()["received_bytes"] == 100

    def test_default_settings_apply_a_real_finite_limit(self) -> None:
        """Guards against a future accidental default of "unlimited"."""
        from kingsec.infrastructure.config import Settings

        assert 0 < Settings().middleware.max_request_body_bytes <= 100 * 1024 * 1024

    def test_a_real_chunked_transfer_encoded_request_cannot_bypass_the_limit(self) -> None:
        """KSEC-86-03 (chunked request-body limit, Phase-84 carry-forward):
        the previous Content-Length-only check could be bypassed entirely
        by a client using Transfer-Encoding: chunked, which carries no
        Content-Length header at all. Passing a generator as the request
        content makes httpx negotiate a real chunked transfer (confirmed:
        the request actually sent carries a `transfer-encoding: chunked`
        header and NO `content-length` header at all - this is a genuine
        HTTP client behavior, not a synthetic ASGI-level construction)."""
        app = self._build_app_via_real_registration(max_request_body_bytes=10)
        client = TestClient(app, raise_server_exceptions=False)

        def chunked_body():
            yield b"x" * 6
            yield b"x" * 6  # 12 bytes total, over the 10-byte limit

        resp = client.post("/api/v1/test", content=chunked_body())

        assert resp.status_code == 413

    def test_a_real_chunked_request_within_the_limit_still_reaches_the_route(self) -> None:
        app = self._build_app_via_real_registration(max_request_body_bytes=100)
        client = TestClient(app, raise_server_exceptions=False)

        def chunked_body():
            yield b"x" * 5
            yield b"x" * 5  # 10 bytes total, under the 100-byte limit

        resp = client.post("/api/v1/test", content=chunked_body())

        assert resp.status_code == 200
        assert resp.json()["received_bytes"] == 10
