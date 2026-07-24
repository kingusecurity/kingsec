"""Security headers middleware.

Injects standard HTTP security headers into every response. Configuration
comes from ``SecurityHeadersSettings``. Headers are set after the response
is generated so they don't interfere with application-level headers.

Documentation route CSP
    API endpoints receive the strict ``default-src 'none'`` policy from
    ``SecurityHeadersSettings``.  Documentation routes (``/docs``, ``/redoc``)
    receive a relaxed policy defined in ``DOCS_CSP`` so that Swagger UI and
    ReDoc can load their required CDN assets (CSS, JS, fonts, images).

    To swap to a self-hosted Swagger bundle in the future, change only the
    ``DOCS_CSP`` constant — no other code needs to change.
"""

from __future__ import annotations

from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from kingsec.infrastructure.config.models import SecurityHeadersSettings

# CSP for API documentation routes (/docs, /redoc).
# Relaxed just enough for Swagger UI and ReDoc to load from CDN.
# Replace this constant with a self-hosted CSP when swagger-ui-dist is
# bundled locally (v1.1+):
#
#   DOCS_CSP = (
#     "default-src 'none'; "
#     "script-src 'self' 'unsafe-inline'; "
#     "style-src 'self' 'unsafe-inline'; "
#     "img-src 'self' data:; "
#     "connect-src 'self'"
#   )
DOCS_CSP = (
    "default-src 'none'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://cdn.jsdelivr.net; "
    "connect-src 'self'; "
    "font-src https://cdn.jsdelivr.net"
)

# Route prefixes that receive the relaxed documentation CSP.
DOCS_PATHS = ("/docs", "/redoc")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware that adds security headers to every response."""

    def __init__(self, app: Any, settings: SecurityHeadersSettings) -> None:
        super().__init__(app)
        self._settings = settings

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = self._settings.x_content_type_options
        response.headers["X-Frame-Options"] = self._settings.x_frame_options
        response.headers["Referrer-Policy"] = self._settings.referrer_policy

        if request.url.path.startswith(DOCS_PATHS):
            response.headers["Content-Security-Policy"] = DOCS_CSP
        else:
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
