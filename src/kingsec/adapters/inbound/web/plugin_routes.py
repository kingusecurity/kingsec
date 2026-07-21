from __future__ import annotations

import os
import tempfile
from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, status

from kingsec.application.ports.plugin_service import PluginServicePort
from kingsec.domain import Role

from .auth import CurrentUser, get_current_user
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1/plugins", tags=["plugins"])

ADMIN_ONLY = Role.ADMIN


def _get_service(request: Request) -> PluginServicePort:
    app: Application = get_application(request)
    return cast(PluginServicePort, app.resolve(PluginServicePort))


def _require_admin(user: CurrentUser) -> None:
    if user.role != ADMIN_ONLY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")


async def _save_upload(file: UploadFile) -> str:
    suffix = ".zip" if file.filename and file.filename.endswith(".zip") else ".tmp"
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        content = await file.read()
        with os.fdopen(fd, "wb") as f:
            f.write(content)
    except Exception:
        os.unlink(path)
        raise
    return path


@router.get("")
async def list_plugins(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_service(request)
    plugins = service.list_plugins()
    return {
        "plugins": [
            {
                "id": p.id,
                "name": p.manifest.name,
                "version": str(p.manifest.version),
                "status": p.status.value,
                "health": p.health.value,
                "author": p.manifest.author,
                "description": p.manifest.description,
            }
            for p in plugins
        ]
    }


@router.get("/updates")
async def check_updates(
    request: Request,
    plugin_id: str,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    updates = service.check_updates(plugin_id)
    return {"plugin_id": plugin_id, "updates": updates}


@router.get("/{plugin_id}")
async def get_plugin(
    plugin_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_service(request)
    plugin = service.get_plugin(plugin_id)
    if not plugin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Plugin '{plugin_id}' not found")
    return {
        "id": plugin.id,
        "name": plugin.manifest.name,
        "version": str(plugin.manifest.version),
        "description": plugin.manifest.description,
        "author": plugin.manifest.author,
        "license": plugin.manifest.license,
        "status": plugin.status.value,
        "health": plugin.health.value,
        "install_path": plugin.install_path,
        "installed_at": plugin.installed_at,
        "error_message": plugin.error_message,
        "checksum_verified": plugin.checksum_verified,
        "signature_verified": plugin.signature_verified,
        "entry_point": plugin.manifest.entry_point,
        "homepage": plugin.manifest.homepage,
        "repository": plugin.manifest.repository,
        "tags": list(plugin.manifest.tags),
    }


@router.post("/install")
async def install_plugin(
    request: Request,
    file: UploadFile,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    path = await _save_upload(file)
    try:
        plugin = service.install(path, file.filename or "plugin.zip")
    except Exception as exc:
        if os.path.exists(path):
            os.unlink(path)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    finally:
        if os.path.exists(path):
            os.unlink(path)
    return {
        "message": f"Plugin '{plugin.manifest.name}' installed successfully",
        "plugin": {
            "id": plugin.id,
            "name": plugin.manifest.name,
            "version": str(plugin.manifest.version),
            "status": plugin.status.value,
        },
    }


@router.post("/uninstall")
async def uninstall_plugin(
    request: Request,
    plugin_id: str,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        service.uninstall(plugin_id)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": f"Plugin '{plugin_id}' uninstalled successfully"}


@router.post("/enable")
async def enable_plugin(
    request: Request,
    plugin_id: str,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        plugin = service.enable(plugin_id)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": f"Plugin '{plugin_id}' enabled",
        "plugin": {"id": plugin.id, "status": plugin.status.value},
    }


@router.post("/disable")
async def disable_plugin(
    request: Request,
    plugin_id: str,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        plugin = service.disable(plugin_id)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": f"Plugin '{plugin_id}' disabled",
        "plugin": {"id": plugin.id, "status": plugin.status.value},
    }


@router.post("/update")
async def update_plugin(
    request: Request,
    plugin_id: str,
    file: UploadFile,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    path = await _save_upload(file)
    try:
        plugin = service.update(plugin_id, path, file.filename or "plugin.zip")
    except Exception as exc:
        if os.path.exists(path):
            os.unlink(path)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    finally:
        if os.path.exists(path):
            os.unlink(path)
    return {
        "message": f"Plugin '{plugin_id}' updated to version {plugin.manifest.version}",
        "plugin": {
            "id": plugin.id,
            "version": str(plugin.manifest.version),
            "status": plugin.status.value,
        },
    }


@router.post("/rollback")
async def rollback_plugin(
    request: Request,
    plugin_id: str,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    try:
        plugin = service.rollback(plugin_id)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {
        "message": f"Plugin '{plugin_id}' rolled back",
        "plugin": {
            "id": plugin.id if plugin else plugin_id,
            "status": plugin.status.value if plugin else "rolled_back",
        },
    }


@router.post("/validate")
async def validate_plugin(
    request: Request,
    file: UploadFile,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    path = await _save_upload(file)
    try:
        result = service.validate(path)
    except Exception as exc:
        if os.path.exists(path):
            os.unlink(path)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    finally:
        if os.path.exists(path):
            os.unlink(path)
    return result


@router.post("/import")
async def import_plugin(
    request: Request,
    file: UploadFile,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    path = await _save_upload(file)
    try:
        plugin = service.import_plugin(path, file.filename or "plugin.zip")
    except Exception as exc:
        if os.path.exists(path):
            os.unlink(path)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    finally:
        if os.path.exists(path):
            os.unlink(path)
    return {
        "message": f"Plugin '{plugin.manifest.name}' imported successfully",
        "plugin": {
            "id": plugin.id,
            "name": plugin.manifest.name,
            "version": str(plugin.manifest.version),
            "status": plugin.status.value,
        },
    }


@router.get("/export/{plugin_id}")
async def export_plugin(
    plugin_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(user)
    service = _get_service(request)
    data = service.export_plugin(plugin_id)
    if data is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Plugin '{plugin_id}' not found")
    return {"plugin_id": plugin_id, "data": data.hex()}
