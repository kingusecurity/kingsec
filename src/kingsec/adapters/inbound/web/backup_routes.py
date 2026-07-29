from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request, status

from kingsec.application.errors import (
    BackupNotFoundError,
    RecoveryPlanNotFoundError,
    RecoveryTestNotFoundError,
    ScheduleNotFoundError,
    SnapshotNotFoundError,
)
from kingsec.application.ports.backup_service import BackupServicePort
from kingsec.domain import Role
from kingsec.domain.backup import (
    BackupMetadata,
    BackupSchedule,
    DisasterRecoveryPlan,
    RecoveryChecklistItem,
    ScheduleFrequency,
)

from .auth import CurrentUser, get_current_user
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1", tags=["backups"])

ADMIN_ONLY = Role.ADMIN


def _get_service(request: Request) -> BackupServicePort:
    app: Application = get_application(request)
    return cast(BackupServicePort, app.resolve(BackupServicePort))


def _require_admin(user: CurrentUser) -> None:
    if user.role != ADMIN_ONLY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")


def _backup_to_dict(backup: BackupMetadata) -> dict[str, Any]:
    return {
        "backup_id": backup.backup_id.value,
        "backup_type": backup.backup_type.value,
        "status": backup.status.value,
        "size_bytes": backup.size_bytes,
        "checksum": backup.checksum,
        "encrypted": backup.encrypted,
        "compressed": backup.compressed,
        "file_path": backup.file_path,
        "owner_user_id": backup.owner_user_id,
        "created_at": backup.created_at,
        "completed_at": backup.completed_at,
        "error_message": backup.error_message,
    }


@router.get("/backups")
async def list_backups(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    backups = service.list_backups()
    return {"backups": [_backup_to_dict(b) for b in backups], "total": len(backups)}


@router.post("/backups")
async def create_backup(
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        backup = service.create_backup(
            backup_type=body.get("backup_type", "full"),
            owner_user_id=body.get("owner_user_id", user.user_id),
            includes=body.get("includes"),
            encrypt=body.get("encrypt", True),
            compress=body.get("compress", True),
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {"message": "Backup created", "backup": _backup_to_dict(backup)}


@router.get("/backups/{backup_id}")
async def get_backup(
    backup_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    backups = service.list_backups()
    for b in backups:
        if b.backup_id.value == backup_id:
            return _backup_to_dict(b)
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Backup '{backup_id}' not found")


@router.delete("/backups/{backup_id}")
async def delete_backup(
    backup_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        service.delete_backup(backup_id)
    except BackupNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": f"Backup '{backup_id}' deleted"}


@router.post("/backups/{backup_id}/restore")
async def restore_backup(
    backup_id: str,
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        operation = service.restore_backup(backup_id, body.get("target_path", ""))
    except BackupNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": f"Restore of '{backup_id}' {'completed' if operation.status.value == 'completed' else 'started'}",
        "restore_id": operation.restore_id.value,
        "status": operation.status.value,
    }


@router.post("/backups/{backup_id}/verify")
async def verify_backup(
    backup_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        valid = service.validate_backup(backup_id)
    except BackupNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"backup_id": backup_id, "valid": valid}


@router.post("/backups/cleanup")
async def cleanup_backups(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    deleted = service.cleanup_expired()
    return {"message": f"Cleaned up {deleted} expired backups", "deleted": deleted}


@router.get("/snapshots")
async def list_snapshots(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    snapshots = service.list_snapshots()
    return {
        "snapshots": [
            {
                "snapshot_id": s.snapshot_id.value,
                "label": s.label,
                "created_at": s.created_at,
                "size_bytes": s.size_bytes,
            }
            for s in snapshots
        ],
        "total": len(snapshots),
    }


@router.post("/snapshots")
async def create_snapshot(
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        snapshot = service.create_snapshot(
            label=body.get("label", ""),
            backup_ids=body.get("backup_ids"),
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {
        "message": "Snapshot created",
        "snapshot": {
            "snapshot_id": snapshot.snapshot_id.value,
            "label": snapshot.label,
            "created_at": snapshot.created_at,
        },
    }


@router.post("/snapshots/{snapshot_id}/restore")
async def restore_snapshot(
    snapshot_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        operation = service.restore_snapshot(snapshot_id)
    except SnapshotNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": f"Snapshot '{snapshot_id}' restore {'completed' if operation.status.value == 'completed' else 'started'}",
        "restore_id": operation.restore_id.value,
        "status": operation.status.value,
    }


# ---------------------------------------------------------------------------
# Enhanced Restore (scope + dry-run)
# ---------------------------------------------------------------------------

@router.post("/backups/{backup_id}/restore-scope")
async def restore_with_scope(
    backup_id: str,
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        operation = service.restore_with_scope(
            backup_id,
            scope=body.get("scope", "complete"),
            dry_run=body.get("dry_run", False),
        )
    except BackupNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": f"Restore of '{backup_id}' ({operation.scope}) {'completed' if operation.status.value == 'completed' else 'started'}",
        "restore_id": operation.restore_id.value,
        "status": operation.status.value,
        "scope": operation.scope,
        "dry_run": operation.dry_run,
    }


# ---------------------------------------------------------------------------
# Backup Verification
# ---------------------------------------------------------------------------

@router.post("/backups/{backup_id}/verify-full")
async def verify_backup_full(
    backup_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        verification = service.verify_backup(backup_id, verified_by=user.user_id)
    except BackupNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "verification_id": verification.verification_id.value,
        "backup_id": verification.backup_id,
        "checksum_valid": verification.checksum_valid,
        "archive_integrity": verification.archive_integrity,
        "restore_simulation": verification.restore_simulation,
        "duration_ms": verification.duration_ms,
        "error_message": verification.error_message,
    }


@router.get("/backup-verifications")
async def list_verifications(
    request: Request,
    backup_id: str | None = None,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    verifications = service.list_verifications(backup_id)
    return {
        "verifications": [
            {
                "verification_id": v.verification_id.value,
                "backup_id": v.backup_id,
                "checksum_valid": v.checksum_valid,
                "archive_integrity": v.archive_integrity,
                "restore_simulation": v.restore_simulation,
                "verified_at": v.verified_at,
                "verified_by": v.verified_by,
                "error_message": v.error_message,
                "duration_ms": v.duration_ms,
            }
            for v in verifications
        ],
        "total": len(verifications),
    }


# ---------------------------------------------------------------------------
# Backup Schedules
# ---------------------------------------------------------------------------

@router.get("/backup-schedules")
async def list_schedules(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    schedules = service.list_schedules()
    return {
        "schedules": [
            {
                "schedule_id": s.schedule_id.value,
                "name": s.name,
                "frequency": s.frequency.value if hasattr(s.frequency, 'value') else str(s.frequency),
                "backup_type": s.backup_type,
                "includes": list(s.includes),
                "encrypt": s.encrypt,
                "compress": s.compress,
                "cron_expression": s.cron_expression,
                "enabled": s.enabled,
                "last_run_at": s.last_run_at,
                "next_run_at": s.next_run_at,
                "created_at": s.created_at,
                "created_by": s.created_by,
            }
            for s in schedules
        ],
        "total": len(schedules),
    }


@router.post("/backup-schedules")
async def create_schedule(
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    from uuid import uuid4
    from kingsec.domain.backup import BackupId
    schedule = BackupSchedule(
        schedule_id=BackupId(value=f"sched-{uuid4().hex[:12]}"),
        name=body.get("name", ""),
        frequency=ScheduleFrequency(body.get("frequency", "manual")),
        backup_type=body.get("backup_type", "full"),
        includes=tuple(body.get("includes", [])),
        encrypt=body.get("encrypt", True),
        compress=body.get("compress", True),
        cron_expression=body.get("cron_expression", ""),
        enabled=body.get("enabled", True),
        created_by=user.user_id,
    )
    created = service.create_schedule(schedule)
    return {
        "message": "Schedule created",
        "schedule": {
            "schedule_id": created.schedule_id.value,
            "name": created.name,
            "frequency": created.frequency.value if hasattr(created.frequency, 'value') else str(created.frequency),
        },
    }


@router.put("/backup-schedules/{schedule_id}")
async def update_schedule(
    schedule_id: str,
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        updated = service.update_schedule(schedule_id, **body)
    except ScheduleNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": "Schedule updated",
        "schedule": {
            "schedule_id": updated.schedule_id.value,
            "name": updated.name,
            "frequency": updated.frequency.value if hasattr(updated.frequency, 'value') else str(updated.frequency),
        },
    }


@router.delete("/backup-schedules/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        service.delete_schedule(schedule_id)
    except ScheduleNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": f"Schedule '{schedule_id}' deleted"}


# ---------------------------------------------------------------------------
# Disaster Recovery Plans
# ---------------------------------------------------------------------------

@router.get("/recovery-plans")
async def list_recovery_plans(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    plans = service.list_recovery_plans()
    return {
        "plans": [
            {
                "plan_id": p.plan_id.value,
                "name": p.name,
                "description": p.description,
                "estimated_downtime_minutes": p.estimated_downtime_minutes,
                "checklist_count": len(p.checklist),
                "last_tested_at": p.last_tested_at,
                "status": p.status,
                "created_at": p.created_at,
                "created_by": p.created_by,
            }
            for p in plans
        ],
        "total": len(plans),
    }


@router.post("/recovery-plans")
async def create_recovery_plan(
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    from uuid import uuid4
    from kingsec.domain.backup import BackupId
    checklist_items = [
        RecoveryChecklistItem(item_id=str(uuid4())[:8], description=c.get("description", ""))
        for c in body.get("checklist", [])
    ]
    plan = DisasterRecoveryPlan(
        plan_id=BackupId(value=f"dr-{uuid4().hex[:12]}"),
        name=body.get("name", ""),
        description=body.get("description", ""),
        estimated_downtime_minutes=body.get("estimated_downtime_minutes", 0),
        checklist=tuple(checklist_items),
        created_by=user.user_id,
    )
    created = service.create_recovery_plan(plan)
    return {
        "message": "Recovery plan created",
        "plan": {
            "plan_id": created.plan_id.value,
            "name": created.name,
        },
    }


@router.get("/recovery-plans/{plan_id}")
async def get_recovery_plan(
    plan_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        plan = service.get_recovery_plan(plan_id)
    except RecoveryPlanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "plan": {
            "plan_id": plan.plan_id.value,
            "name": plan.name,
            "description": plan.description,
            "estimated_downtime_minutes": plan.estimated_downtime_minutes,
            "checklist": [{"item_id": c.item_id, "description": c.description, "completed": c.completed} for c in plan.checklist],
            "last_tested_at": plan.last_tested_at,
            "status": plan.status,
            "created_at": plan.created_at,
            "created_by": plan.created_by,
        }
    }


@router.put("/recovery-plans/{plan_id}")
async def update_recovery_plan(
    plan_id: str,
    request: Request,
    body: dict[str, Any],
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        updated = service.update_recovery_plan(plan_id, **body)
    except RecoveryPlanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": "Recovery plan updated",
        "plan": {"plan_id": updated.plan_id.value, "name": updated.name},
    }


@router.delete("/recovery-plans/{plan_id}")
async def delete_recovery_plan(
    plan_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        service.delete_recovery_plan(plan_id)
    except RecoveryPlanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": f"Recovery plan '{plan_id}' deleted"}


@router.post("/recovery-plans/{plan_id}/test")
async def test_recovery(
    plan_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        test = service.test_recovery(plan_id, executed_by=user.user_id)
    except RecoveryPlanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": "Recovery test completed",
        "test": {
            "test_id": test.test_id.value,
            "plan_id": test.plan_id,
            "status": test.status.value if hasattr(test.status, 'value') else str(test.status),
            "started_at": test.started_at,
            "completed_at": test.completed_at,
            "executed_by": test.executed_by,
        },
    }


@router.get("/recovery-tests")
async def list_recovery_tests(
    request: Request,
    plan_id: str | None = None,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    tests = service.list_recovery_tests(plan_id)
    return {
        "tests": [
            {
                "test_id": t.test_id.value,
                "plan_id": t.plan_id,
                "status": t.status.value if hasattr(t.status, 'value') else str(t.status),
                "started_at": t.started_at,
                "completed_at": t.completed_at,
                "executed_by": t.executed_by,
            }
            for t in tests
        ],
        "total": len(tests),
    }


# ---------------------------------------------------------------------------
# High Availability Health
# ---------------------------------------------------------------------------

@router.get("/backup-health")
async def get_backup_health(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    report = service.get_health_report()
    return {
        "report_id": report.report_id.value,
        "overall": report.overall.value if hasattr(report.overall, 'value') else str(report.overall),
        "database_healthy": report.database_healthy,
        "storage_healthy": report.storage_healthy,
        "workers_healthy": report.workers_healthy,
        "backup_service_healthy": report.backup_service_healthy,
        "generated_at": report.generated_at,
        "components": [
            {
                "component": c.component,
                "health": c.health.value if hasattr(c.health, 'value') else str(c.health),
                "message": c.message,
                "checked_at": c.checked_at,
            }
            for c in report.components
        ],
    }
