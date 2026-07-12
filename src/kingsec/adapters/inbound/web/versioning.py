"""API version routing.

Isolates version-specific routing so adding ``/api/v2/`` later requires
only creating a new router and registering it — no business logic changes.

Current versions:
    - v1: ``/api/v1/...`` (all existing endpoints)

To add v2:
    1. Create ``routes_v2.py`` with new/modified endpoints.
    2. Register the v2 router in ``register_versioned_routes()``.
    3. v1 remains unchanged.
"""

from __future__ import annotations

from fastapi import FastAPI

from .routes import router as v1_router
from .sse import router as v1_sse_router


def register_versioned_routes(app: FastAPI) -> None:
    """Register all versioned API routers on the FastAPI application.

    Current: v1 only. Architecture ready for v2+.
    """
    # v1 routes
    app.include_router(v1_router)
    app.include_router(v1_sse_router)

    # Future example:
    # from .routes_v2 import router as v2_router
    # app.include_router(v2_router)
