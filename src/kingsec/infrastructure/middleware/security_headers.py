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

SPA route CSP
    Everything that isn't an ``/api/*`` or documentation path is either the
    bundled frontend (served by ``spa.py``'s static mount/fallback) or a
    genuinely unmatched path that the SPA fallback still answers with
    ``index.html``. ``default-src 'none'`` would break the SPA outright —
    no script execution, no stylesheets, no fetch() to the API — so those
    responses get ``SPA_CSP`` instead: still no external origins (the
    frontend is 100% self-hosted, zero CDN, per its own tech constraints),
    just permitting same-origin script/style/img/connect/worker.

Permissions-Policy
    A restrictive Permissions-Policy header is added to all responses,
    disabling browser features that have no use in an API context (camera,
    microphone, geolocation, etc.).
"""

from __future__ import annotations

import secrets
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from kingsec.infrastructure.config.models import SecurityHeadersSettings

_LOCALHOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})

# CSP for API documentation routes (/docs, /redoc).
# Relaxed just enough for Swagger UI and ReDoc to load from CDN.
# Replace this constant with a self-hosted CSP when swagger-ui-dist is
# bundled locally (v1.1+):
#
#   DOCS_CSP = (
#       "default-src 'none'; "
#       "script-src 'self' 'unsafe-inline'; "
#       "style-src 'self' 'unsafe-inline'; "
#       "img-src 'self' data:; "
#       "connect-src 'self'"
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

# CSP for the bundled frontend SPA (everything not under /api or the docs
# paths). Self-hosted only — the build has zero CDN/external-request
# dependencies — so this stays tight: no 'unsafe-inline', no 'unsafe-eval',
# no third-party origins anywhere.
SPA_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "manifest-src 'self'; "
    "worker-src 'self'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

# Path prefix under which every real API route lives (see
# adapters/inbound/web/versioning.py) — anything outside this and
# DOCS_PATHS is the SPA's territory.
_API_PREFIX = "/api"

# Default Permissions-Policy: disable all browser features not needed by an API.
_DEFAULT_PERMISSIONS_POLICY = (
    "camera=(), microphone=(), geolocation=(), payment=(), "
    "usb=(), magnetometer=(), gyroscope=(), accelerometer=(), "
    "ambient-light-sensor=(), autoplay=(), battery=(), "
    "bluetooth=(), browsing-topics=(), document-domain=(), "
    "encrypted-media=(), execution-while-not-rendered=(), "
    "execution-while-out-of-viewport=(), fullscreen=(), "
    "gamepad=(), gyroscope=(), inert=(), keyboard-map=(), "
    "magnetometer=(), midi=(), navigation-override=(), "
    "payment=(), picture-in-picture=(), publickey-credentials-get=(), "
    "screen-wake-lock=(), sync-xhr=(), usb=(), "
    "web-share=(), xr-spatial-tracking=()"
)


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

        # Permissions-Policy: disable unnecessary browser features.
        response.headers["Permissions-Policy"] = _DEFAULT_PERMISSIONS_POLICY

        # Content-Security-Policy with optional nonce support.
        if request.url.path.startswith(DOCS_PATHS):
            response.headers["Content-Security-Policy"] = DOCS_CSP
        elif not request.url.path.startswith(_API_PREFIX) and request.url.path != "/openapi.json":
            response.headers["Content-Security-Policy"] = SPA_CSP
        else:
            csp = self._settings.content_security_policy
            # If CSP contains 'nonce-', generate a per-request nonce.
            if "nonce-" in csp:
                nonce = secrets.token_urlsafe(32)
                csp = csp.replace("nonce-", f"nonce-{nonce}")
                response.headers["Content-Security-Policy"] = csp
                response.headers["X-Content-Security-Policy-Nonce"] = nonce
            else:
                response.headers["Content-Security-Policy"] = csp

        if self._settings.hsts_max_age > 0:
            host = request.url.hostname or ""
            is_localhost_http = host in _LOCALHOSTS and request.url.scheme == "http"
            if not is_localhost_http:
                response.headers["Strict-Transport-Security"] = (
                    f"max-age={self._settings.hsts_max_age}; includeSubDomains; preload"
                )

        if self._settings.remove_server_header:
            for key in ("server", "Server"):
                if key in response.headers:
                    del response.headers[key]

        if self._settings.remove_x_powered_by:
            for key in ("x-powered-by", "X-Powered-By"):
                if key in response.headers:
                    del response.headers[key]

        return response
