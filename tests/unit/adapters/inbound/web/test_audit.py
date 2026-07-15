"""Tests for audit web adapter — EnrichedAuditPublisher and admin query route."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from kingsec.domain.audit import AuditAction, AuditEntry


class InMemoryAuditPublisher:
    """Test double for AuditPublisher that records entries in memory."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        self.entries.append(entry)


class TestEnrichedAuditPublisher:
    def test_enriches_with_request_context(self) -> None:
        from starlette.testclient import TestClient as StarletteClient
        from starlette.requests import Request
        from starlette.responses import Response
        from starlette.routing import Route
        from kingsec.adapters.inbound.web.audit import EnrichedAuditPublisher

        inner = InMemoryAuditPublisher()

        async def _endpoint(request: Request) -> Response:
            # Simulate middleware setting state.
            request.state.audit_ip = "192.168.1.1"
            request.state.audit_user_agent = "TestAgent/1.0"
            request.state.audit_correlation_id = "corr-123"

            publisher = EnrichedAuditPublisher(inner, request)
            publisher.record(AuditEntry(action=AuditAction.LOGIN, user_id="user-1"))
            return Response("ok")

        app = FastAPI(routes=[Route("/test", _endpoint)])
        client = TestClient(app, raise_server_exceptions=False)
        client.get("/test")

        assert len(inner.entries) == 1
        entry = inner.entries[0]
        assert entry.ip_address == "192.168.1.1"
        assert entry.user_agent == "TestAgent/1.0"
        assert entry.correlation_id == "corr-123"

    def test_does_not_overwrite_existing_context(self) -> None:
        from starlette.requests import Request
        from starlette.responses import Response
        from starlette.routing import Route
        from kingsec.adapters.inbound.web.audit import EnrichedAuditPublisher

        inner = InMemoryAuditPublisher()

        async def _endpoint(request: Request) -> Response:
            request.state.audit_ip = "192.168.1.1"
            request.state.audit_user_agent = "TestAgent/1.0"
            request.state.audit_correlation_id = "corr-123"

            publisher = EnrichedAuditPublisher(inner, request)
            publisher.record(AuditEntry(
                action=AuditAction.LOGIN,
                ip_address="10.0.0.1",
                user_agent="ExistingAgent",
                correlation_id="existing-id",
            ))
            return Response("ok")

        app = FastAPI(routes=[Route("/test", _endpoint)])
        client = TestClient(app, raise_server_exceptions=False)
        client.get("/test")

        entry = inner.entries[0]
        # Existing values preserved, not overwritten.
        assert entry.ip_address == "10.0.0.1"
        assert entry.user_agent == "ExistingAgent"
        assert entry.correlation_id == "existing-id"


class TestAuditContextMiddleware:
    def test_sets_audit_context(self) -> None:
        from kingsec.infrastructure.audit.context import AuditContextMiddleware

        app = FastAPI()
        app.add_middleware(AuditContextMiddleware)

        @app.get("/test")
        async def test_endpoint(request: Request):
            return {
                "ip": getattr(request.state, "audit_ip", None),
                "user_agent": getattr(request.state, "audit_user_agent", None),
                "correlation_id": getattr(request.state, "audit_correlation_id", None),
            }

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/test", headers={"User-Agent": "TestAgent/1.0"})
        data = resp.json()
        assert data["ip"] == "testclient"
        assert data["user_agent"] == "TestAgent/1.0"
        assert data["correlation_id"] is not None  # empty string if no CorrelationIDMiddleware

    def test_uses_correlation_id_from_correlation_middleware(self) -> None:
        from kingsec.infrastructure.audit.context import AuditContextMiddleware
        from kingsec.infrastructure.middleware.correlation_id import CorrelationIDMiddleware

        app = FastAPI()
        app.add_middleware(AuditContextMiddleware)
        app.add_middleware(CorrelationIDMiddleware)

        @app.get("/test")
        async def test_endpoint(request: Request):
            return {
                "correlation_id": getattr(request.state, "audit_correlation_id", None),
                "request_id": getattr(request.state, "request_id", None),
            }

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/test", headers={"X-Request-ID": "my-trace-id"})
        data = resp.json()
        assert data["correlation_id"] == "my-trace-id"
        assert data["request_id"] == "my-trace-id"
