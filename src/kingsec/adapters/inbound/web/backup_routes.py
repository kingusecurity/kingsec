from __future__ import annotations

from typing import TYPE_CHECKING

from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request, status

from kingsec.application.errors import BackupNotFoundError, SnapshotNotFoundError
from kingsec.application.ports.backup_service import BackupServicePort
from kingsec.domain import Role
from kingsec.domain.backup import BackupMetadata

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
