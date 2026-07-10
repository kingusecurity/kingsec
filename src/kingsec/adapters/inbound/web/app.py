"""FastAPI application factory.

Builds the FastAPI instance, wires routes, error handlers, and stores the
KingSec ``Application`` on ``app.state`` so the dependency layer can reach it.

The factory does NOT start the KingSec application — that is the caller's
responsibility (see ``__main__.py``). This separation keeps the FastAPI
app independently testable: tests can create it with a stubbed ``ServiceAPI``
without running the full composition root.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI

from .error_handlers import register_error_handlers
from .routes import router

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

    app = FastAPI(
        title="KingSec API",
        version=kingsec_app.settings.app.version,
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

    # Error handlers (must be registered before routes).
    register_error_handlers(app)

    # Routes.
    app.include_router(router)

    return app
