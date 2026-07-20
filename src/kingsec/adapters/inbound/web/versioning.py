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

from .audit import router as v1_audit_router
from .audit_events import router as v1_audit_events_router
from .mfa_routes import router as v1_mfa_router
from .routes import router as v1_router
from .schedule_routes import router as v1_schedule_router
from .secret_routes import router as v1_secret_router
from .session_routes import router as v1_sessions_router
from .sse import router as v1_sse_router
from .notification_routes import router as v1_notification_router
from .dashboard_routes import router as v1_dashboard_router
from .plugin_routes import router as v1_plugin_router
from .agent_routes import router as v1_agent_router
from .queue_routes import router as v1_queue_router
from .pipeline_routes import router as v1_pipeline_router
from .backup_routes import router as v1_backup_router


def register_versioned_routes(app: FastAPI) -> None:
    """Register all versioned API routers on the FastAPI application.

    Current: v1 only. Architecture ready for v2+.
    """
    # v1 routes
    app.include_router(v1_router)
    app.include_router(v1_sse_router)
    app.include_router(v1_audit_router)
    app.include_router(v1_audit_events_router)
    app.include_router(v1_mfa_router)
    app.include_router(v1_schedule_router)
    app.include_router(v1_secret_router)
    app.include_router(v1_sessions_router)
    app.include_router(v1_notification_router)
    app.include_router(v1_dashboard_router)
    app.include_router(v1_plugin_router)
    app.include_router(v1_agent_router)
    app.include_router(v1_queue_router)
    app.include_router(v1_pipeline_router)
    app.include_router(v1_backup_router)

    # Future example:
    # from .routes_v2 import router as v2_router
    # app.include_router(v2_router)
