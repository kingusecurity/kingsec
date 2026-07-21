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
    6. Audit Context
    7. Request Logging
    8. Rate Limiting
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI

from .error_handlers import register_error_handlers
from .openapi import configure_openapi
from .versioning import register_versioned_routes

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application


def create_fastapi_app(
    kingsec_app: Application,
    *,
    register_middleware: Callable[..., Any] | None = None,
) -> FastAPI:
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
        description=("Local-first, AI-augmented Attack Surface & Vulnerability Management API"),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # Store the KingSec application for the dependency layer.
    app.state.kingsec_app = kingsec_app

    # Configure OpenAPI specification.
    configure_openapi(app, settings.app)

    # Register middleware (order matters: last added = outermost).
    if register_middleware:
        register_middleware(app, settings)

    # Error handlers (must be registered before routes).
    register_error_handlers(app)

    # Versioned routes (v1, future v2+).
    register_versioned_routes(app)

    return app
