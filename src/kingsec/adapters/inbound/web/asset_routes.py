from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request

from kingsec.application.ports.asset_inventory import AssetFilter, AssetSummary
from kingsec.application.services.asset_inventory import AssetInventoryService
from kingsec.application.errors import AssetNotFoundError
from kingsec.domain.asset import Asset, AssetCriticality, AssetType

from .auth import CurrentUser, get_current_user, require_analyst
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1", tags=["asset-inventory"])


def _get_service(request: Request) -> AssetInventoryService:
    app: Application = get_application(request)
    svc = app.resolve(AssetInventoryService)
    if svc is None:
        raise HTTPException(status_code=500, detail="AssetInventoryService not available")
    return cast(AssetInventoryService, svc)


def _asset_to_dict(asset: Asset) -> dict[str, Any]:
    return {
        "id": str(asset.id),
        "asset_type": asset.asset_type.value,
        "hostname": asset.hostname,
        "ip_address": asset.ip_address,
        "domain": asset.domain,
        "fqdn": asset.fqdn,
        "mac_address": asset.mac_address,
        "operating_system": asset.operating_system,
        "os_version": asset.os_version,
        "criticality": asset.criticality.value,
        "owner": asset.owner,
        "location": asset.location,
        "description": asset.description,
        "tags": [{"key": t.key, "value": t.value} for t in asset.tags],
        "services": [{"name": s.name, "port": s.port, "protocol": s.protocol} for s in asset.services],
        "technologies": [
            {"type": t.technology_type, "name": t.name, "version": t.version, "vendor": t.vendor}
            for t in asset.technologies
        ],
        "open_ports": list(asset.open_ports),
        "risk_score": asset.risk_score,
        "first_seen": asset.first_seen,
        "last_seen": asset.last_seen,
        "created_at": asset.created_at,
        "updated_at": asset.updated_at,
    }


# =====================================================================
#  CRUD
# =====================================================================


@router.get("/assets/summary")
def get_asset_summary(
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> AssetSummary:
    return _get_service(request).get_asset_summary()


@router.get("/assets")
def list_assets(
    request: Request,
    asset_type: str | None = None,
    criticality: str | None = None,
    search: str | None = None,
    owner: str | None = None,
    location: str | None = None,
    cloud_provider: str | None = None,
    risk_score_min: float | None = None,
    risk_score_max: float | None = None,
    limit: int = 50,
    offset: int = 0,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    filter_ = AssetFilter(
        asset_type=AssetType(asset_type) if asset_type else None,
        criticality=criticality,
        search=search,
        owner=owner,
        location=location,
        cloud_provider=cloud_provider,
        risk_score_min=risk_score_min,
        risk_score_max=risk_score_max,
    )
    svc = _get_service(request)
    items = svc.list_assets(filter_, limit=limit, offset=offset)
    total = svc.count_assets(filter_)
    return {
        "items": [_asset_to_dict(a) for a in items],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/assets/search")
def search_assets(
    request: Request,
    q: str = "",
    limit: int = 20,
    _user: CurrentUser = Depends(require_analyst),
) -> list[dict[str, Any]]:
    items = _get_service(request).search_assets(q, limit=limit)
    return [_asset_to_dict(a) for a in items]


@router.get("/assets/{asset_id}")
def get_asset(
    asset_id: str,
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        svc = _get_service(request)
        detail = svc.get_asset_detail(asset_id)
        result = _asset_to_dict(detail.asset)
        result["relationships"] = [
            {
                "source_asset_id": r.source_asset_id,
                "target_asset_id": r.target_asset_id,
                "relationship_type": r.relationship_type,
                "metadata": r.metadata,
            }
            for r in detail.relationships
        ]
        result["history"] = [
            {
                "event_type": h.event_type,
                "description": h.description,
                "timestamp": h.timestamp,
                "actor": h.actor,
            }
            for h in detail.history
        ]
        result["finding_count"] = detail.finding_count
        return result
    except (AssetNotFoundError, KeyError) as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/assets")
def create_asset(
    body: dict[str, Any],
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    asset_type = AssetType(body.get("asset_type", "host"))
    asset = _get_service(request).create_asset(
        asset_type,
        hostname=body.get("hostname"),
        ip_address=body.get("ip_address"),
        domain=body.get("domain"),
        fqdn=body.get("fqdn"),
        mac_address=body.get("mac_address"),
        operating_system=body.get("operating_system"),
        os_version=body.get("os_version"),
        criticality=AssetCriticality(body.get("criticality", "medium")),
        owner=body.get("owner"),
        location=body.get("location"),
        description=body.get("description"),
    )
    return _asset_to_dict(asset)


@router.put("/assets/{asset_id}")
def update_asset(
    asset_id: str,
    body: dict[str, Any],
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        asset = _get_service(request).update_asset(asset_id, body)
        return _asset_to_dict(asset)
    except (AssetNotFoundError, KeyError) as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/assets/{asset_id}")
def delete_asset(
    asset_id: str,
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, str]:
    try:
        _get_service(request).delete_asset(asset_id)
        return {"status": "deleted"}
    except AssetNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


# =====================================================================
#  Tags
# =====================================================================


@router.post("/assets/{asset_id}/tags")
def add_tag(
    asset_id: str,
    body: dict[str, str],
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        asset = _get_service(request).add_tag(asset_id, body["key"], body["value"])
        return _asset_to_dict(asset)
    except AssetNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/assets/{asset_id}/tags/{key}")
def remove_tag(
    asset_id: str,
    key: str,
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        asset = _get_service(request).remove_tag(asset_id, key)
        return _asset_to_dict(asset)
    except AssetNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


# =====================================================================
#  Relationships
# =====================================================================


@router.get("/assets/{asset_id}/relationships")
def get_relationships(
    asset_id: str,
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> list[dict[str, Any]]:
    rels = _get_service(request).get_relationships(asset_id)
    return [
        {
            "source_asset_id": r.source_asset_id,
            "target_asset_id": r.target_asset_id,
            "relationship_type": r.relationship_type,
            "metadata": r.metadata,
        }
        for r in rels
    ]


@router.post("/assets/{asset_id}/relationships")
def add_relationship(
    asset_id: str,
    body: dict[str, Any],
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    rel = _get_service(request).add_relationship(
        source_id=asset_id,
        target_id=body["target_asset_id"],
        rel_type=body.get("relationship_type", "connected_to"),
        metadata=body.get("metadata"),
    )
    return {
        "source_asset_id": rel.source_asset_id,
        "target_asset_id": rel.target_asset_id,
        "relationship_type": rel.relationship_type,
        "metadata": rel.metadata,
    }


# =====================================================================
#  Risk & Criticality
# =====================================================================


@router.post("/assets/{asset_id}/recalculate-risk")
def recalculate_risk(
    asset_id: str,
    body: dict[str, int],
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        asset = _get_service(request).recalculate_risk(
            asset_id,
            critical_findings=body.get("critical_findings", 0),
            high_findings=body.get("high_findings", 0),
            open_findings=body.get("open_findings", 0),
        )
        return {"risk_score": asset.risk_score}
    except AssetNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.put("/assets/{asset_id}/criticality")
def update_criticality(
    asset_id: str,
    body: dict[str, str],
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        asset = _get_service(request).update_criticality(asset_id, body["criticality"])
        return _asset_to_dict(asset)
    except AssetNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


# =====================================================================
#  History
# =====================================================================


@router.get("/assets/{asset_id}/history")
def get_asset_history(
    asset_id: str,
    request: Request,
    limit: int = 50,
    _user: CurrentUser = Depends(require_analyst),
) -> list[dict[str, Any]]:
    history = _get_service(request).get_history(asset_id, limit=limit)
    return [
        {
            "event_type": h.event_type,
            "description": h.description,
            "timestamp": h.timestamp,
            "previous_value": h.previous_value,
            "new_value": h.new_value,
            "actor": h.actor,
        }
        for h in history
    ]
