"""Correlation / Request ID middleware.

Generates a unique request ID for every incoming request and adds it to
the response headers. If the client provides an ``X-Request-ID`` header,
it is forwarded (useful for distributed tracing). Otherwise, a new UUID
is generated.

The request ID is stored on ``request.state.request_id`` for use by
other middleware and route handlers.
"""

from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """Middleware that adds a correlation/request ID to every request/response."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex)
        request.state.request_id = request_id  # type: ignore[attr-defined]

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id

        return response
