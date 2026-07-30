from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request

from kingsec.application.errors import ExposureNotFoundError
from kingsec.application.ports.attack_surface import AttackSurfaceSummary, ExposureFilter
from kingsec.application.services.attack_surface import AttackSurfaceService
from kingsec.domain.attack_surface import Exposure, ExposureRisk, ExposureSeverity, ExposureType

from .auth import CurrentUser, require_analyst
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1", tags=["attack-surface"])


def _get_service(request: Request) -> AttackSurfaceService:
    app: Application = get_application(request)
    svc = app.resolve(AttackSurfaceService)
    if svc is None:
        raise HTTPException(status_code=500, detail="AttackSurfaceService not available")
    return cast(AttackSurfaceService, svc)


def _exposure_to_dict(e: Exposure) -> dict[str, Any]:
    return {
        "id": str(e.id),
        "asset_id": e.asset_id,
        "exposure_type": e.exposure_type.value,
        "severity": e.severity.value,
        "title": e.title,
        "description": e.description,
        "detail": [{"key": d.key, "value": d.value} for d in e.detail],
        "status": e.status.value,
        "source": e.source,
        "port": e.port,
        "protocol": e.protocol,
        "hostname": e.hostname,
        "ip_address": e.ip_address,
        "domain": e.domain,
        "url": e.url,
        "tls_version": e.tls_version,
        "certificate_issuer": e.certificate_issuer,
        "certificate_expiry": e.certificate_expiry,
        "header_name": e.header_name,
        "header_value": e.header_value,
        "technology_name": e.technology_name,
        "technology_version": e.technology_version,
        "cloud_provider": e.cloud_provider,
        "cloud_bucket": e.cloud_bucket,
        "evidence": e.evidence,
        "remediation": e.remediation,
        "risk_score": e.risk_score,
        "first_seen": e.first_seen,
        "last_seen": e.last_seen,
        "created_at": e.created_at,
        "updated_at": e.updated_at,
    }


# =====================================================================
#  Summary & Overview
# =====================================================================


@router.get("/attack-surface/summary")
def get_attack_surface_summary(
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> AttackSurfaceSummary:
    return _get_service(request).get_summary()


@router.get("/attack-surface/risk")
def get_attack_surface_risk(
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> ExposureRisk:
    return _get_service(request).get_exposure_risk()


@router.get("/attack-surface/trend")
def get_attack_surface_trend(
    request: Request,
    days: int = 30,
    _user: CurrentUser = Depends(require_analyst),
) -> list[dict[str, Any]]:
    return _get_service(request).get_exposure_trend(days=days)


@router.get("/attack-surface/assets")
def get_assets_with_exposures(
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> list[str]:
    return _get_service(request).get_assets_with_exposures()


# =====================================================================
#  CRUD
# =====================================================================


@router.get("/attack-surface/exposures")
def list_exposures(
    request: Request,
    asset_id: str | None = None,
    exposure_type: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    source: str | None = None,
    search: str | None = None,
    risk_score_min: float | None = None,
    risk_score_max: float | None = None,
    limit: int = 50,
    offset: int = 0,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    filter_ = ExposureFilter(
        asset_id=asset_id,
        exposure_type=ExposureType(exposure_type) if exposure_type else None,
        severity=ExposureSeverity(severity) if severity else None,
        status=status,
        source=source,
        search=search,
        risk_score_min=risk_score_min,
        risk_score_max=risk_score_max,
    )
    svc = _get_service(request)
    items = svc.list_exposures(filter_, limit=limit, offset=offset)
    total = svc.count_exposures(filter_)
    return {
        "items": [_exposure_to_dict(e) for e in items],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/attack-surface/exposures/search")
def search_exposures(
    request: Request,
    q: str = "",
    limit: int = 20,
    _user: CurrentUser = Depends(require_analyst),
) -> list[dict[str, Any]]:
    items = _get_service(request).search_exposures(q, limit=limit)
    return [_exposure_to_dict(e) for e in items]


@router.get("/attack-surface/exposures/{exposure_id}")
def get_exposure(
    exposure_id: str,
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        e = _get_service(request).get_exposure(exposure_id)
        return _exposure_to_dict(e)
    except ExposureNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/attack-surface/exposures")
def create_exposure(
    body: dict[str, Any],
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    exposure_type = ExposureType(body.get("exposure_type", "open_port"))
    severity = ExposureSeverity(body["severity"]) if body.get("severity") else None
    e = _get_service(request).record_exposure(
        body["asset_id"],
        exposure_type,
        severity=severity,
        title=body.get("title", ""),
        description=body.get("description", ""),
        source=body.get("source", "scanner"),
        port=body.get("port"),
        protocol=body.get("protocol"),
        hostname=body.get("hostname"),
        ip_address=body.get("ip_address"),
        domain=body.get("domain"),
        url=body.get("url"),
        tls_version=body.get("tls_version"),
        certificate_issuer=body.get("certificate_issuer"),
        certificate_expiry=body.get("certificate_expiry"),
        header_name=body.get("header_name"),
        header_value=body.get("header_value"),
        technology_name=body.get("technology_name"),
        technology_version=body.get("technology_version"),
        cloud_provider=body.get("cloud_provider"),
        cloud_bucket=body.get("cloud_bucket"),
        evidence=body.get("evidence"),
        remediation=body.get("remediation"),
    )
    return _exposure_to_dict(e)


@router.put("/attack-surface/exposures/{exposure_id}")
def update_exposure(
    exposure_id: str,
    body: dict[str, Any],
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        e = _get_service(request).update_exposure(exposure_id, body)
        return _exposure_to_dict(e)
    except ExposureNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/attack-surface/exposures/{exposure_id}")
def delete_exposure(
    exposure_id: str,
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, str]:
    try:
        _get_service(request).delete_exposure(exposure_id)
        return {"status": "deleted"}
    except ExposureNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


# =====================================================================
#  Asset Exposures
# =====================================================================


@router.get("/attack-surface/assets/{asset_id}/exposures")
def get_asset_exposures(
    asset_id: str,
    request: Request,
    limit: int = 50,
    offset: int = 0,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    svc = _get_service(request)
    items = svc.get_asset_exposures(asset_id, limit=limit, offset=offset)
    total = svc.count_asset_exposures(asset_id)
    return {
        "items": [_exposure_to_dict(e) for e in items],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# =====================================================================
#  Mitigation & Risk
# =====================================================================


@router.post("/attack-surface/exposures/{exposure_id}/mitigate")
def mitigate_exposure(
    exposure_id: str,
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        e = _get_service(request).mitigate_exposure(exposure_id)
        return _exposure_to_dict(e)
    except ExposureNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.put("/attack-surface/exposures/{exposure_id}/remediation")
def update_remediation(
    exposure_id: str,
    body: dict[str, str],
    request: Request,
    _user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    try:
        e = _get_service(request).update_exposure_remediation(exposure_id, body["remediation"])
        return _exposure_to_dict(e)
    except ExposureNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


# =====================================================================
#  History
# =====================================================================


@router.get("/attack-surface/exposures/{exposure_id}/history")
def get_exposure_history(
    exposure_id: str,
    request: Request,
    limit: int = 50,
    _user: CurrentUser = Depends(require_analyst),
) -> list[dict[str, Any]]:
    history = _get_service(request).get_exposure_history(exposure_id, limit=limit)
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


# =====================================================================
#  High Risk
# =====================================================================


@router.get("/attack-surface/high-risk")
def get_high_risk_exposures(
    request: Request,
    min_score: float = 50.0,
    _user: CurrentUser = Depends(require_analyst),
) -> list[dict[str, Any]]:
    items = _get_service(request).get_high_risk_exposures(min_score=min_score)
    return [_exposure_to_dict(e) for e in items]
