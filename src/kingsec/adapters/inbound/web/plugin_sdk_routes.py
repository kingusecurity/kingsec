from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from kingsec.domain.plugin_extensions import PluginPermission, PluginType

from .auth import CurrentUser, get_current_user, require_admin
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.application.plugin_sdk.registry import PluginMarketplace, PluginRegistry
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1/plugin-sdk", tags=["Plugin SDK"])


def _get_registry(request: Request, _: CurrentUser = Depends(get_current_user)) -> Any:
    from kingsec.application.plugin_sdk.registry import PluginRegistry
    app: Application = get_application(request)
    return app.resolve(PluginRegistry)


def _get_marketplace(request: Request, _: CurrentUser = Depends(get_current_user)) -> Any:
    from kingsec.application.plugin_sdk.registry import PluginMarketplace
    app: Application = get_application(request)
    return app.resolve(PluginMarketplace)


@router.get("/plugins")
def list_sdk_plugins(
    type_filter: str | None = Query(None, alias="type"),
    registry: PluginRegistry = Depends(_get_registry),
) -> dict[str, Any]:
    runtimes = registry.list_runtimes()
    if type_filter:
        try:
            ptype = PluginType(type_filter)
            runtimes = registry.list_by_type(ptype)
        except ValueError:
            pass
    return {
        "plugins": [
            {
                "id": r.id,
                "name": r.name,
                "version": r.version,
                "type": r.type.value,
                "permissions": [p.value for p in r.permissions],
                "loaded": r.loaded,
                "entry_point": r.entry_point,
                "error": r.error,
            }
            for r in runtimes
        ],
        "total": len(runtimes),
    }


@router.get("/plugins/{plugin_id}")
def get_sdk_plugin(
    plugin_id: str,
    registry: PluginRegistry = Depends(_get_registry),
) -> dict[str, Any]:
    runtime = registry.get_runtime(plugin_id)
    if not runtime:
        raise HTTPException(status_code=404, detail="Plugin not found")
    manifest = registry.get_manifest(plugin_id)
    return {
        "id": runtime.id,
        "name": runtime.name,
        "version": runtime.version,
        "type": runtime.type.value,
        "permissions": [p.value for p in runtime.permissions],
        "loaded": runtime.loaded,
        "entry_point": runtime.entry_point,
        "error": runtime.error,
        "manifest": manifest.to_dict() if manifest else None,
    }


@router.post("/plugins/scan")
def scan_plugins(
    registry: PluginRegistry = Depends(_get_registry),
    _: CurrentUser = Depends(require_admin),
) -> dict[str, Any]:
    manifests = registry.discover()
    return {
        "message": f"Discovered {len(manifests)} plugin(s)",
        "count": len(manifests),
    }


@router.post("/plugins/{plugin_id}/load")
def load_plugin(
    plugin_id: str,
    registry: PluginRegistry = Depends(_get_registry),
    _: CurrentUser = Depends(require_admin),
) -> dict[str, Any]:
    runtime = registry.load_plugin(plugin_id)
    if not runtime:
        raise HTTPException(status_code=404, detail="Failed to load plugin")
    if runtime.error:
        raise HTTPException(status_code=400, detail=runtime.error)
    return {
        "message": f"Plugin '{runtime.name}' loaded successfully",
        "plugin": {
            "id": runtime.id,
            "name": runtime.name,
            "loaded": runtime.loaded,
        },
    }


@router.post("/plugins/{plugin_id}/unload")
def unload_plugin(
    plugin_id: str,
    registry: PluginRegistry = Depends(_get_registry),
    _: CurrentUser = Depends(require_admin),
) -> dict[str, Any]:
    registry.unload_plugin(plugin_id)
    return {"message": f"Plugin '{plugin_id}' unloaded"}


@router.get("/marketplace/available")
def list_available_plugins(
    type_filter: str | None = Query(None, alias="type"),
    search: str | None = Query(None),
    marketplace: PluginMarketplace = Depends(_get_marketplace),
) -> dict[str, Any]:
    if search:
        entries = marketplace.search(search)
    elif type_filter:
        try:
            ptype = PluginType(type_filter)
            entries = marketplace.filter_by_type(ptype)
        except ValueError:
            entries = marketplace.list_available()
    else:
        entries = marketplace.list_available()
    return {
        "plugins": [
            {
                "id": e.plugin_id,
                "name": e.name,
                "version": e.version,
                "author": e.author,
                "description": e.description,
                "category": e.category.value,
                "license": e.license,
                "website": e.website,
                "downloads": e.downloads,
                "rating": e.rating,
                "verified": e.verified,
                "tags": list(e.tags),
            }
            for e in entries
        ],
        "total": len(entries),
    }


@router.get("/marketplace/plugin/{plugin_id}")
def get_marketplace_plugin(
    plugin_id: str,
    marketplace: PluginMarketplace = Depends(_get_marketplace),
) -> dict[str, Any]:
    entry = marketplace.get_entry(plugin_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Plugin not found in marketplace")
    return {
        "id": entry.plugin_id,
        "name": entry.name,
        "version": entry.version,
        "author": entry.author,
        "description": entry.description,
        "category": entry.category.value,
        "license": entry.license,
        "website": entry.website,
        "downloads": entry.downloads,
        "rating": entry.rating,
        "verified": entry.verified,
        "tags": list(entry.tags),
    }


@router.get("/permissions")
def list_permissions() -> dict[str, Any]:
    return {
        "permissions": [p.value for p in PluginPermission],
        "types": [t.value for t in PluginType],
    }
