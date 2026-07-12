"""Structured request logging middleware.

Logs every HTTP request with structured fields: method, path, status code,
duration, client IP, and request ID. Uses structlog for consistent,
machine-parseable output.

Security considerations:
    - Does NOT log request bodies (may contain passwords/tokens).
    - Does NOT log Authorization header values.
    - Request ID is included for correlation.
"""

from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from kingsec.infrastructure.logging import get_logger

_logger = get_logger("kingsec.http.access")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs structured request/response information."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start = time.perf_counter()
        request_id = getattr(request.state, "request_id", "unknown")

        response = await call_next(request)

        duration_ms = (time.perf_counter() - start) * 1000
        client_ip = request.client.host if request.client else "unknown"

        _logger.info(
            "http_request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=round(duration_ms, 2),
            client_ip=client_ip,
            request_id=request_id,
        )

        return response
