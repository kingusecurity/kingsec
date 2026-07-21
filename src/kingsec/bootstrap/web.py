"""Web-layer wiring — middleware registration and FastAPI assembly helpers.

This module is the ONLY place adapters' web layer touches infrastructure.
It is allowed to import from ``kingsec.infrastructure`` because bootstrap is
the composition root; nothing else in ``kingsec.adapters`` should import it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

if TYPE_CHECKING:
    from fastapi import FastAPI
    from kingsec.infrastructure.config.settings import Settings


def register_middleware(app: FastAPI, settings: Settings) -> None:
    """Register all middleware in the correct order.

    Middleware is executed in reverse registration order, so the last
    middleware added is the outermost (executes first).
    """
    from kingsec.infrastructure.middleware import (
        AuditContextMiddleware,
        CorrelationIDMiddleware,
        RateLimitMiddleware,
        RequestLoggingMiddleware,
        SecurityHeadersMiddleware,
    )

    # Rate limiting (innermost — runs after all other middleware).
    app.add_middleware(RateLimitMiddleware, settings=settings.rate_limit)

    # Request logging.
    if settings.middleware.request_logging:
        app.add_middleware(RequestLoggingMiddleware)

    # Correlation ID.
    app.add_middleware(CorrelationIDMiddleware)

    # Audit context (must run AFTER CorrelationID so request_id is available).
    app.add_middleware(AuditContextMiddleware)

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
