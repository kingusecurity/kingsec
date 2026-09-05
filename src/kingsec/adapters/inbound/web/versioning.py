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

from .agent_routes import router as v1_agent_router
from .ai_provider_routes import router as v1_ai_provider_router
from .ai_routes import router as v1_ai_router
from .asset_routes import router as v1_asset_router
from .attack_surface_routes import router as v1_attack_surface_router
from .audit import router as v1_audit_router
from .audit_events import router as v1_audit_events_router
from .backup_routes import router as v1_backup_router
from .compliance_routes import router as v1_compliance_router
from .copilot_routes import router as v1_copilot_router
from .dashboard_routes import router as v1_dashboard_router
from .deployment_routes import router as v1_deployment_router
from .distributed_routes import router as v1_distributed_queue_router
from .execution_inspection_routes import router as v1_execution_inspection_router
from .execution_routes import router as v1_execution_router
from .health_routes import router as v1_health_router
from .identity_routes import router as v1_identity_router
from .integration_routes import router as v1_integration_router
from .license_routes import router as v1_license_router
from .metrics_routes import router as v1_metrics_router
from .mfa_routes import router as v1_mfa_router
from .monitoring_routes import router as v1_monitoring_router
from .notification_routes import router as v1_notification_router
from .organization_routes import router as v1_organization_router
from .pipeline_routes import router as v1_pipeline_router
from .playbook_routes import router as v1_playbook_router
from .plugin_routes import router as v1_plugin_router
from .plugin_sdk_routes import router as v1_plugin_sdk_router
from .profiles_routes import router as v1_profiles_router
from .queue_routes import router as v1_queue_router
from .routes import router as v1_router
from .scanner_discovery_routes import router as v1_scanner_discovery_router
from .schedule_routes import router as v1_schedule_router
from .secret_routes import router as v1_secret_router
from .session_routes import router as v1_sessions_router
from .sse import router as v1_sse_router
from .threat_intelligence_routes import router as v1_threat_intelligence_router
from .worker_routes import router as v1_worker_router


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
    app.include_router(v1_execution_router)
    app.include_router(v1_execution_inspection_router)
    app.include_router(v1_plugin_router)
    app.include_router(v1_agent_router)
    app.include_router(v1_queue_router)
    app.include_router(v1_pipeline_router)
    app.include_router(v1_profiles_router)
    app.include_router(v1_scanner_discovery_router)
    app.include_router(v1_backup_router)
    app.include_router(v1_ai_router)
    app.include_router(v1_ai_provider_router)
    app.include_router(v1_asset_router)
    app.include_router(v1_attack_surface_router)
    app.include_router(v1_health_router)
    app.include_router(v1_compliance_router)
    app.include_router(v1_monitoring_router)
    app.include_router(v1_playbook_router)
    app.include_router(v1_plugin_sdk_router)
    app.include_router(v1_integration_router)
    app.include_router(v1_organization_router)
    app.include_router(v1_license_router)
    app.include_router(v1_threat_intelligence_router)
    app.include_router(v1_copilot_router)
    app.include_router(v1_distributed_queue_router)
    app.include_router(v1_identity_router)
    app.include_router(v1_metrics_router)
    app.include_router(v1_worker_router)
    app.include_router(v1_deployment_router)

    # Future example:
    # from .routes_v2 import router as v2_router
    # app.include_router(v2_router)
