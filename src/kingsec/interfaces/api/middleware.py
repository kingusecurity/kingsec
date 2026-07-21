"""Production-grade FastAPI middleware for the KingSec API.

Stack order (outermost → innermost):
  1. Structured Logging
  2. Request Timing
  3. Request ID
  4. Security Headers
  5. GZip
  6. CORS

No business logic.  No scanner / renderer / report imports.
"""

from __future__ import annotations

import time
import uuid

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware

from kingsec.infrastructure.logging import get_logger

# ============================================================================
# Logger
# ============================================================================

_request_logger = get_logger("kingsec.api.request")


# ============================================================================
# 1.  Request ID Middleware
# ============================================================================


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Attach a unique request ID to every request.

    * Honour ``X-Request-ID`` from the client if present.
    * Generate UUID4 otherwise.
    * Store in ``scope["request_id"]`` for downstream middleware.
    * Set ``request.state.request_id`` for endpoint access.
    * Always set ``X-Request-ID`` response header.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        client_id = request.headers.get("X-Request-ID")
        if client_id:
            request.scope["request_id"] = client_id
        else:
            request.scope.setdefault("request_id", str(uuid.uuid4()))

        request.state.request_id = request.scope["request_id"]

        response = await call_next(request)

        response.headers["X-Request-ID"] = request.scope["request_id"]
        return response


# ============================================================================
# 2.  Request Timing Middleware
# ============================================================================


class RequestTimingMiddleware(BaseHTTPMiddleware):
    """Measure total processing time.

    Stores elapsed milliseconds in ``scope["process_time"]`` and sets
    ``X-Process-Time`` response header (ms with three decimal places).
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        response.headers["X-Process-Time"] = f"{elapsed_ms:.3f}"
        request.scope["process_time"] = elapsed_ms
        request.state.process_time = elapsed_ms
        return response


# ============================================================================
# 3.  Security Headers Middleware
# ============================================================================


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add standard security headers to every response."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Permissions-Policy"] = "interest-cohort=()"
        return response


# ============================================================================
# 4.  Structured Logging Middleware
# ============================================================================


class LoggingMiddleware(BaseHTTPMiddleware):
    """Log every completed request at INFO level.

    Fields: request_id, method, path, status, elapsed_ms.
    No request or response bodies are logged.
    No secrets are exposed.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        try:
            response = await call_next(request)
        except Exception:
            request_id = request.scope.get("request_id", "unknown")
            _request_logger.info(
                "request failed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status=500,
                elapsed_ms=0.0,
            )
            raise
        request_id = request.scope.get("request_id", "unknown")
        elapsed_str = response.headers.get("X-Process-Time", "0")
        try:
            elapsed = float(elapsed_str)
        except (ValueError, TypeError):
            elapsed = 0.0
        _request_logger.info(
            "request completed",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            elapsed_ms=round(elapsed, 3),
        )
        return response


# ============================================================================
# 5.  Registration helper
# ============================================================================


def register_middleware(app: FastAPI) -> None:
    """Register all standard middleware on the FastAPI application.

    Must be called inside ``create_app()`` after the app is instantiated.
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost", "http://127.0.0.1"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(GZipMiddleware, minimum_size=1024)

    app.add_middleware(SecurityHeadersMiddleware)

    app.add_middleware(RequestIDMiddleware)

    app.add_middleware(RequestTimingMiddleware)

    app.add_middleware(LoggingMiddleware)
