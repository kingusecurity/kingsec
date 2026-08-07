"""Tests for security headers middleware."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.infrastructure.config.models import SecurityHeadersSettings
from kingsec.infrastructure.middleware.security_headers import SecurityHeadersMiddleware


def _build_app(settings: SecurityHeadersSettings | None = None) -> FastAPI:
    app = FastAPI()

    @app.get("/api/test")
    async def test_endpoint():
        return {"ok": True}

    if settings is None:
        settings = SecurityHeadersSettings()

    app.add_middleware(SecurityHeadersMiddleware, settings=settings)
    return app


class TestSecurityHeaders:
    def test_x_content_type_options(self) -> None:
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/test")
        assert resp.headers["X-Content-Type-Options"] == "nosniff"

    def test_x_frame_options(self) -> None:
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/test")
        assert resp.headers["X-Frame-Options"] == "DENY"

    def test_referrer_policy(self) -> None:
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/test")
        assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"

    def test_content_security_policy(self) -> None:
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/test")
        assert resp.headers["Content-Security-Policy"] == "default-src 'none'"

    def test_custom_settings(self) -> None:
        settings = SecurityHeadersSettings(
            x_frame_options="SAMEORIGIN",
            referrer_policy="no-referrer",
        )
        app = _build_app(settings)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/test")
        assert resp.headers["X-Frame-Options"] == "SAMEORIGIN"
        assert resp.headers["Referrer-Policy"] == "no-referrer"

    def test_no_server_header(self) -> None:
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/test")
        assert "server" not in resp.headers
        assert "Server" not in resp.headers
