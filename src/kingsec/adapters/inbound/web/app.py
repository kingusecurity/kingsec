"""FastAPI application factory.

Builds the FastAPI instance, wires routes, error handlers, middleware, and
stores the KingSec ``Application`` on ``app.state`` so the dependency layer
can reach it.

The factory does NOT start the KingSec application — that is the caller's
responsibility (see ``__main__.py``). This separation keeps the FastAPI
app independently testable: tests can create it with a stubbed ``ServiceAPI``
without running the full composition root.

Middleware is registered in the correct order (outermost first):
    1. GZip compression
    2. Trusted Host
    3. CORS
    4. Security Headers
    5. Correlation ID
    6. Request Logging
    7. Rate Limiting
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from kingsec.infrastructure.config.settings import Settings
from kingsec.infrastructure.middleware import (
    CorrelationIDMiddleware,
    RateLimitMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
)

from .error_handlers import register_error_handlers
from .openapi import configure_openapi
from .versioning import register_versioned_routes

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application


def create_fastapi_app(kingsec_app: Application) -> FastAPI:
    """Build a configured FastAPI application.

    Args:
        kingsec_app: A started KingSec ``Application`` instance whose
            container has a ``ServiceAPI`` registered.

    Returns:
        A ready-to-serve ``FastAPI`` instance.
    """

    settings = kingsec_app.settings

    app = FastAPI(
        title="KingSec API",
        version=settings.app.version,
        description=(
            "Local-first, AI-augmented Attack Surface & Vulnerability "
            "Management API"
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # Store the KingSec application for the dependency layer.
    app.state.kingsec_app = kingsec_app  # type: ignore[attr-defined]

    # Configure OpenAPI specification.
    configure_openapi(app, settings.app)

    # Register middleware (order matters: last added = outermost).
    _register_middleware(app, settings)

    # Error handlers (must be registered before routes).
    register_error_handlers(app)

    # Versioned routes (v1, future v2+).
    register_versioned_routes(app)

    return app


def _register_middleware(app: FastAPI, settings: Settings) -> None:
    """Register all middleware in the correct order.

    Middleware is executed in reverse registration order, so the last
    middleware added is the outermost (executes first).
    """

    # Rate limiting (innermost — runs after all other middleware).
    app.add_middleware(RateLimitMiddleware, settings=settings.rate_limit)

    # Request logging.
    if settings.middleware.request_logging:
        app.add_middleware(RequestLoggingMiddleware)

    # Correlation ID.
    app.add_middleware(CorrelationIDMiddleware)

    # Security headers.
    app.add_middleware(SecurityHeadersMiddleware, settings=settings.security_headers)

    # CORS.
    if settings.cors.allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors.allow_origins,
            allow_methods=settings.cors.allow_methods,
            allow_headers=settings.cors.allow_headers,
            allow_credentials=settings.cors.allow_credentials,
            expose_headers=settings.cors.expose_headers,
            max_age=settings.cors.max_age,
        )

    # Trusted hosts.
    if settings.middleware.trusted_hosts:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.middleware.trusted_hosts,
        )

    # GZip compression.
    if settings.middleware.gzip_enabled:
        app.add_middleware(
            GZipMiddleware,
            minimum_size=settings.middleware.gzip_minimum_size,
        )
