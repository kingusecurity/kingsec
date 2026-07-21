"""Audit context middleware — captures HTTP request metadata for audit entries.

Stores the current request's IP address, user-agent, and correlation ID
on ``request.state`` so the web adapter's enriched publisher can attach
them to audit entries without passing HTTP context through use cases.

This middleware MUST run AFTER ``CorrelationIDMiddleware`` so the
correlation ID is already available on ``request.state``.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class AuditContextMiddleware(BaseHTTPMiddleware):
    """Middleware that captures audit-relevant HTTP context per request.

    Stores the following on ``request.state``:
        - ``audit_ip``: Client IP address.
        - ``audit_user_agent``: Client User-Agent header.
        - ``audit_correlation_id``: Correlation ID (from CorrelationIDMiddleware).
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Capture audit-relevant context before passing to the next middleware.
        request.state.audit_ip = request.client.host if request.client else "unknown"
        request.state.audit_user_agent = request.headers.get("user-agent", "")
        # CorrelationIDMiddleware stores this; fall back to empty string.
        request.state.audit_correlation_id = getattr(
            request.state, "request_id", ""
        )

        return await call_next(request)
