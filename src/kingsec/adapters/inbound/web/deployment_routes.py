"""Deployment, diagnostics, release-audit and telemetry routes.

Exposes the previously-unwired infrastructure services
(``DiagnosticsCollector``, ``UpgradeService``, ``ReleaseAuditService``,
``ProductTelemetry``) over HTTP. Admin-only: this surface reveals host
paths, environment variables and log excerpts.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse

from kingsec.domain import Role
from kingsec.infrastructure.audit.release_audit import ReleaseAuditService
from kingsec.infrastructure.monitoring.diagnostics import (
    DiagnosticsCollector,
    create_diagnostics_bundle,
)
from kingsec.infrastructure.telemetry.product_telemetry import ProductTelemetry
from kingsec.infrastructure.upgrade.upgrade_service import UpgradeService

from .auth import CurrentUser, get_current_user
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1", tags=["Deployment"])

ADMIN_ONLY = Role.ADMIN


def _require_admin(user: CurrentUser) -> None:
    if user.role != ADMIN_ONLY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")


def _get_diagnostics(request: Request) -> DiagnosticsCollector:
    app: Application = get_application(request)
    return cast(DiagnosticsCollector, app.resolve(DiagnosticsCollector))


def _get_upgrade_service(request: Request) -> UpgradeService:
    app: Application = get_application(request)
    return cast(UpgradeService, app.resolve(UpgradeService))


def _get_release_audit(request: Request) -> ReleaseAuditService:
    app: Application = get_application(request)
    return cast(ReleaseAuditService, app.resolve(ReleaseAuditService))


def _get_telemetry(request: Request) -> ProductTelemetry:
    app: Application = get_application(request)
    return cast(ProductTelemetry, app.resolve(ProductTelemetry))


@router.get("/deployment/system-info")
def get_system_info(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    return _get_diagnostics(request).collect_system_info()


@router.get("/deployment/config")
def get_config_summary(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    return _get_diagnostics(request).collect_config_summary()


@router.get("/deployment/diagnostics")
def get_diagnostics(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    return _get_diagnostics(request).collect_all()


@router.get("/deployment/diagnostics/bundle")
def download_diagnostics_bundle(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> FileResponse:
    _require_admin(user)
    app: Application = get_application(request)
    bundle_path = create_diagnostics_bundle(
        data_dir=app.settings.storage.data_dir,
        app_version=app.settings.app.version,
    )
    return FileResponse(
        bundle_path,
        media_type="application/zip",
        filename=bundle_path.name,
    )


@router.get("/deployment/upgrade/plan")
def get_upgrade_plan(
    request: Request,
    target: str = Query(...),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    plan = _get_upgrade_service(request).create_plan(target)
    return {
        "from_version": plan.from_version,
        "to_version": plan.to_version,
        "checks": [asdict(c) for c in plan.checks],
        "migration_steps": list(plan.migration_steps),
        "backup_required": plan.backup_required,
        "estimated_downtime": plan.estimated_downtime,
    }


@router.post("/deployment/upgrade/run")
def run_upgrade(
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    target_version = body.get("target_version", "")
    if not target_version:
        raise HTTPException(status_code=400, detail="target_version is required")

    from kingsec._migrate import run_migrations

    upgrade_service = _get_upgrade_service(request)
    plan = upgrade_service.create_plan(target_version)
    blocking = [c for c in plan.checks if not c.passed and c.severity == "error"]
    if blocking:
        raise HTTPException(
            status_code=409,
            detail=f"Upgrade blocked: {', '.join(c.message for c in blocking)}",
        )

    from_version = plan.from_version
    upgrade_service.create_backup()
    returncode = run_migrations()
    if returncode != 0:
        raise HTTPException(status_code=500, detail="Database migration failed during upgrade")

    upgrade_service.set_installed_version(target_version)
    _get_release_audit(request).record_upgrade(
        from_version=from_version,
        to_version=target_version,
        upgraded_by=user.username,
    )
    return {"status": "completed", "message": f"Upgraded from {from_version} to {target_version}"}


@router.get("/deployment/release-audit")
def get_release_audit_report(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    report = _get_release_audit(request).generate_report()
    return {
        "current_version": report.current_version,
        "installed_at": report.installed_at,
        "total_releases": report.total_releases,
        "releases": [asdict(r) for r in report.releases],
        "upgrade_history": [asdict(r) for r in report.upgrade_history],
    }


@router.post("/deployment/release-audit/record", status_code=201)
def record_release(
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    version = body.get("version")
    if not version:
        raise HTTPException(status_code=400, detail="version is required")
    entry = _get_release_audit(request).record_release(
        version=version,
        release_type=body.get("release_type", "patch"),
        changes=tuple(body.get("changes", [])),
        breaking_changes=tuple(body.get("breaking_changes", [])),
        notes=body.get("notes", ""),
    )
    return asdict(entry)


@router.get("/deployment/telemetry/summary")
def get_telemetry_summary(
    request: Request,
    days: int = Query(30, ge=1, le=365),
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    return _get_telemetry(request).get_summary(days)
