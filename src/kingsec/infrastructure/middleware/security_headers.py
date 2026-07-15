"""Security headers middleware.

Injects standard HTTP security headers into every response. Configuration
comes from ``SecurityHeadersSettings``. Headers are set after the response
is generated so they don't interfere with application-level headers.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from kingsec.infrastructure.config.models import SecurityHeadersSettings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware that adds security headers to every response."""

    def __init__(self, app, settings: SecurityHeadersSettings) -> None:
        super().__init__(app)
        self._settings = settings

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = self._settings.x_content_type_options
        response.headers["X-Frame-Options"] = self._settings.x_frame_options
        response.headers["Referrer-Policy"] = self._settings.referrer_policy
        response.headers["Content-Security-Policy"] = self._settings.content_security_policy

        if self._settings.remove_server_header:
            for key in ("server", "Server"):
                if key in response.headers:
                    del response.headers[key]

        if self._settings.remove_x_powered_by:
            for key in ("x-powered-by", "X-Powered-By"):
                if key in response.headers:
                    del response.headers[key]

        return response
