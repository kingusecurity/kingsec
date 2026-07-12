"""Tests for correlation ID middleware."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.infrastructure.middleware.correlation_id import CorrelationIDMiddleware


def _build_app() -> FastAPI:
    app = FastAPI()

    @app.get("/test")
    async def test_endpoint():
        return {"ok": True}

    app.add_middleware(CorrelationIDMiddleware)
    return app


class TestCorrelationID:
    def test_generates_request_id(self) -> None:
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/test")
        assert "X-Request-ID" in resp.headers
        assert len(resp.headers["X-Request-ID"]) > 0

    def test_forwards_client_request_id(self) -> None:
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/test", headers={"X-Request-ID": "my-custom-id"})
        assert resp.headers["X-Request-ID"] == "my-custom-id"

    def test_generates_unique_ids(self) -> None:
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp1 = client.get("/test")
        resp2 = client.get("/test")
        # Two different requests should get different IDs
        assert resp1.headers["X-Request-ID"] != resp2.headers["X-Request-ID"]
