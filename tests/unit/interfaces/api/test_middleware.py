"""Production middleware: comprehensive tests."""

from __future__ import annotations

import io
import re
import uuid

from fastapi import Request
from fastapi.testclient import TestClient
from structlog.testing import CapturingLogger

from kingsec.interfaces.api.app import create_app
from kingsec.interfaces.api.middleware import (
    LoggingMiddleware,
    RequestIDMiddleware,
    RequestTimingMiddleware,
    SecurityHeadersMiddleware,
    register_middleware,
)


# ============================================================================
# Helpers
# ============================================================================


def _build_app(**kwargs):
    return create_app(**kwargs)


def _app_with_route():
    from fastapi import FastAPI

    app = FastAPI()
    register_middleware(app)

    @app.get("/test")
    async def _test() -> dict:
        return {"ok": True}

    return app


# ============================================================================
# Request ID Middleware
# ============================================================================


class TestRequestIDMiddleware:
    def setup_method(self) -> None:
        self.client = TestClient(_build_app())

    def test_response_has_request_id_header(self) -> None:
        response = self.client.get("/health")
        assert "X-Request-ID" in response.headers

    def test_request_id_is_valid_uuid4(self) -> None:
        response = self.client.get("/health")
        rid = response.headers["X-Request-ID"]
        parsed = uuid.UUID(rid, version=4)
        assert parsed.version == 4

    def test_request_id_honours_incoming_header(self) -> None:
        custom_id = "custom-request-id-123"
        response = self.client.get("/health", headers={"X-Request-ID": custom_id})
        assert response.headers["X-Request-ID"] == custom_id

    def test_request_id_is_unique_per_request(self) -> None:
        r1 = self.client.get("/health")
        r2 = self.client.get("/health")
        assert r1.headers["X-Request-ID"] != r2.headers["X-Request-ID"]

    def test_request_id_on_scope(self) -> None:
        result: list[str | None] = [None]

        app = _app_with_route()

        @app.get("/scope-check")
        async def scope_check(request: Request) -> dict:
            result[0] = request.scope.get("request_id")
            return {"ok": True}

        client = TestClient(app)
        client.get("/scope-check")
        assert result[0] is not None
        parsed = uuid.UUID(result[0], version=4)
        assert parsed.version == 4


class TestExistingRequestID:
    def setup_method(self) -> None:
        self.client = TestClient(_build_app())

    def test_propagates_incoming_request_id(self) -> None:
        incoming = str(uuid.uuid4())
        response = self.client.get("/health", headers={"X-Request-ID": incoming})
        assert response.headers["X-Request-ID"] == incoming

    def test_multiple_requests_with_same_header(self) -> None:
        incoming = str(uuid.uuid4())
        r1 = self.client.get("/health", headers={"X-Request-ID": incoming})
        r2 = self.client.get("/health", headers={"X-Request-ID": incoming})
        assert r1.headers["X-Request-ID"] == incoming
        assert r2.headers["X-Request-ID"] == incoming


# ============================================================================
# Request Timing Middleware
# ============================================================================


class TestRequestTimingMiddleware:
    def setup_method(self) -> None:
        self.client = TestClient(_build_app())

    def test_response_has_process_time_header(self) -> None:
        response = self.client.get("/health")
        assert "X-Process-Time" in response.headers

    def test_process_time_is_positive_float(self) -> None:
        response = self.client.get("/health")
        value = response.headers["X-Process-Time"]
        ms = float(value)
        assert ms > 0

    def test_process_time_format(self) -> None:
        response = self.client.get("/health")
        value = response.headers["X-Process-Time"]
        assert re.match(r"^\d+\.\d{3}$", value)

    def test_multiple_requests_have_timing(self) -> None:
        r1 = self.client.get("/health")
        r2 = self.client.get("/health")
        assert float(r1.headers["X-Process-Time"]) > 0
        assert float(r2.headers["X-Process-Time"]) > 0


# ============================================================================
# Security Headers Middleware
# ============================================================================


class TestSecurityHeadersMiddleware:
    def setup_method(self) -> None:
        self.client = TestClient(_build_app())

    def test_x_content_type_options(self) -> None:
        response = self.client.get("/health")
        assert response.headers["X-Content-Type-Options"] == "nosniff"

    def test_x_frame_options(self) -> None:
        response = self.client.get("/health")
        assert response.headers["X-Frame-Options"] == "DENY"

    def test_referrer_policy(self) -> None:
        response = self.client.get("/health")
        assert response.headers["Referrer-Policy"] == "no-referrer"

    def test_x_xss_protection(self) -> None:
        response = self.client.get("/health")
        assert response.headers["X-XSS-Protection"] == "1; mode=block"

    def test_permissions_policy(self) -> None:
        response = self.client.get("/health")
        assert response.headers["Permissions-Policy"] == "interest-cohort=()"

    def test_all_security_headers_present(self) -> None:
        response = self.client.get("/health")
        expected = {
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
            "x-xss-protection",
            "permissions-policy",
        }
        actual = {k.lower() for k in response.headers}
        assert expected.issubset(actual)

    def test_security_headers_on_error_response(self) -> None:
        response = self.client.get("/nonexistent")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"

    def test_security_headers_on_post(self) -> None:
        response = self.client.post("/health")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"


# ============================================================================
# CORS Middleware
# ============================================================================


class TestCORSMiddleware:
    def setup_method(self) -> None:
        self.client = TestClient(_build_app())

    def test_cors_allow_origin_localhost(self) -> None:
        response = self.client.options(
            "/health",
            headers={
                "Origin": "http://localhost",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.headers.get("Access-Control-Allow-Origin") == "http://localhost"

    def test_cors_allow_origin_127_0_0_1(self) -> None:
        response = self.client.options(
            "/health",
            headers={
                "Origin": "http://127.0.0.1",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.headers.get("Access-Control-Allow-Origin") == "http://127.0.0.1"

    def test_cors_allow_methods(self) -> None:
        response = self.client.options(
            "/health",
            headers={
                "Origin": "http://localhost",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert "GET" in response.headers.get("Access-Control-Allow-Methods", "")

    def test_cors_reflects_requested_headers(self) -> None:
        response = self.client.options(
            "/health",
            headers={
                "Origin": "http://localhost",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        assert "content-type" in response.headers.get("Access-Control-Allow-Headers", "").lower()

    def test_cors_rejects_unknown_origin(self) -> None:
        response = self.client.options(
            "/health",
            headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
        assert "evil.com" not in allow_origin

    def test_cors_simple_request_has_origin(self) -> None:
        response = self.client.get("/health", headers={"Origin": "http://localhost"})
        assert response.headers.get("Access-Control-Allow-Origin") == "http://localhost"


# ============================================================================
# GZip Middleware
# ============================================================================


class TestGZipMiddleware:
    def setup_method(self) -> None:
        self.client = TestClient(_build_app())

    def test_gzip_small_response_not_compressed(self) -> None:
        response = self.client.get("/health", headers={"Accept-Encoding": "gzip"})
        content_encoding = response.headers.get("Content-Encoding", "")
        assert content_encoding != "gzip"

    def test_gzip_large_response_is_compressed(self) -> None:
        from fastapi import FastAPI

        app = FastAPI()
        register_middleware(app)
        large_data = "x" * 2000

        @app.get("/large")
        async def large() -> dict:
            return {"data": large_data}

        client = TestClient(app)
        response = client.get("/large", headers={"Accept-Encoding": "gzip"})
        assert response.headers.get("Content-Encoding") == "gzip"


# ============================================================================
# Structured Logging Middleware
# ============================================================================


_LOG_FIELDS = frozenset({"request_id", "method", "path", "status", "elapsed_ms"})


class TestLoggingMiddleware:
    def setup_method(self) -> None:
        import kingsec.interfaces.api.middleware as mw

        self._original_logger = mw._request_logger
        self.capture = CapturingLogger()
        mw._request_logger = self.capture
        self.client = TestClient(_build_app())

    def teardown_method(self) -> None:
        import kingsec.interfaces.api.middleware as mw

        mw._request_logger = self._original_logger

    @property
    def _call(self) -> CapturingLogger.CapturedCall | None:
        return self.capture.calls[0] if self.capture.calls else None

    def test_logs_request_completed(self) -> None:
        self.client.get("/health")
        assert self._call is not None
        assert self._call.args[0] == "request completed"

    def test_logs_request_id(self) -> None:
        self.client.get("/health")
        assert self._call is not None
        rid = self._call.kwargs["request_id"]
        assert rid is not None
        parsed = uuid.UUID(rid, version=4)
        assert parsed.version == 4

    def test_logs_method(self) -> None:
        self.client.post("/health")
        assert self._call is not None
        assert self._call.kwargs["method"] == "POST"

    def test_logs_path(self) -> None:
        self.client.get("/health")
        assert self._call is not None
        assert self._call.kwargs["path"] == "/health"

    def test_logs_status(self) -> None:
        self.client.get("/health")
        assert self._call is not None
        assert self._call.kwargs["status"] == 200

    def test_logs_elapsed_ms(self) -> None:
        self.client.get("/health")
        assert self._call is not None
        assert self._call.kwargs["elapsed_ms"] > 0

    def test_logs_404(self) -> None:
        self.client.get("/nonexistent")
        assert self._call is not None
        assert self._call.kwargs["status"] == 404

    def test_logs_405(self) -> None:
        self.client.post("/health")
        assert self._call is not None
        assert self._call.kwargs["status"] == 405

    def test_logs_500_without_bodies(self) -> None:
        import kingsec.interfaces.api.middleware as mw

        orig = mw._request_logger
        capture = CapturingLogger()
        mw._request_logger = capture

        from fastapi import FastAPI

        app = FastAPI()
        register_middleware(app)

        @app.get("/crash")
        async def crash() -> None:
            raise RuntimeError("test crash")

        client = TestClient(app, raise_server_exceptions=False)
        client.get("/crash")
        assert capture.calls[0].kwargs["status"] == 500
        mw._request_logger = orig

    def test_does_not_log_request_body(self) -> None:
        self.client.get("/health")
        assert self._call is not None
        assert "request_body" not in self._call.kwargs
        assert "body" not in self._call.kwargs

    def test_does_not_log_response_body(self) -> None:
        self.client.get("/health")
        assert self._call is not None
        assert "response_body" not in self._call.kwargs

    def test_extra_fields_present_on_record(self) -> None:
        self.client.get("/health")
        assert self._call is not None
        for field in _LOG_FIELDS:
            assert field in self._call.kwargs, f"Missing log field: {field}"


# ============================================================================
# Middleware Order Tests
# ============================================================================


class TestMiddlewareOrder:
    def test_middleware_listed_on_app(self) -> None:
        """user_middleware is in reverse-execution order (innermost first)."""
        app = _build_app()
        middlewares = [m.cls for m in app.user_middleware]
        from starlette.middleware.cors import CORSMiddleware
        from starlette.middleware.gzip import GZipMiddleware

        idx_cors = next(i for i, c in enumerate(middlewares) if c is CORSMiddleware)
        idx_gzip = next(i for i, c in enumerate(middlewares) if c is GZipMiddleware)
        idx_security = next(i for i, c in enumerate(middlewares) if c is SecurityHeadersMiddleware)
        idx_rid = next(i for i, c in enumerate(middlewares) if c is RequestIDMiddleware)
        idx_logging = next(i for i, c in enumerate(middlewares) if c is LoggingMiddleware)
        idx_timing = next(i for i, c in enumerate(middlewares) if c is RequestTimingMiddleware)

        # user_middleware index 0 = added last = outermost (request enters first)
        assert idx_logging < idx_timing
        assert idx_timing < idx_rid
        assert idx_rid < idx_security
        assert idx_security < idx_gzip
        assert idx_gzip < idx_cors


# ============================================================================
# Response Headers Combination
# ============================================================================


class TestCombinedHeaders:
    def setup_method(self) -> None:
        self.client = TestClient(_build_app())

    def test_all_custom_headers_present(self) -> None:
        response = self.client.get("/health")
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        assert "x-request-id" in headers_lower
        assert "x-process-time" in headers_lower
        assert "x-content-type-options" in headers_lower
        assert "x-frame-options" in headers_lower
        assert "referrer-policy" in headers_lower
        assert "x-xss-protection" in headers_lower
        assert "permissions-policy" in headers_lower


# ============================================================================
# Multiple Requests
# ============================================================================


class TestMultipleRequests:
    def setup_method(self) -> None:
        self.client = TestClient(_build_app())

    def test_sequential_requests(self) -> None:
        for _ in range(10):
            response = self.client.get("/health")
            assert response.status_code == 200
            assert "X-Request-ID" in response.headers
            assert "X-Process-Time" in response.headers

    def test_concurrent_like_requests(self) -> None:
        results = [self.client.get("/health") for _ in range(20)]
        ids = [r.headers["X-Request-ID"] for r in results]
        assert len(set(ids)) == 20


# ============================================================================
# UUID Validation
# ============================================================================


class TestUUIDValidation:
    def setup_method(self) -> None:
        self.client = TestClient(_build_app())

    def test_uuid_format(self) -> None:
        response = self.client.get("/health")
        rid = response.headers["X-Request-ID"]
        assert re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", rid)

    def test_multiple_uuids_all_valid(self) -> None:
        for _ in range(50):
            response = self.client.get("/health")
            rid = response.headers["X-Request-ID"]
            parsed = uuid.UUID(rid, version=4)
            assert parsed.version == 4


# ============================================================================
# Register function isolated
# ============================================================================


class TestRegisterFunction:
    def test_register_middleware_returns_none(self) -> None:
        from fastapi import FastAPI

        app = FastAPI()
        result = register_middleware(app)
        assert result is None

    def test_register_middleware_adds_middleware(self) -> None:
        from fastapi import FastAPI

        app = FastAPI()
        register_middleware(app)
        assert len(app.user_middleware) == 6
