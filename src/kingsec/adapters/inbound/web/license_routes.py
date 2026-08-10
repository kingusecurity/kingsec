from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from kingsec.application.services.license_key_codec import InvalidLicenseKeyError
from kingsec.application.services.licensing import LicenseActivationService, LicenseGate

from .auth import CurrentUser, get_current_user, require_admin
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1", tags=["licensing"])


def _get_gate(request: Request) -> LicenseGate:
    app: Application = get_application(request)
    gate: LicenseGate | None = app.resolve(LicenseGate)
    if gate is None:
        raise HTTPException(status_code=500, detail="License gate not available")
    return gate


def _get_service(request: Request) -> LicenseActivationService:
    app: Application = get_application(request)
    service: LicenseActivationService | None = app.resolve(LicenseActivationService)
    if service is None:
        raise HTTPException(status_code=500, detail="License service not available")
    return service


@router.get("/license")
async def get_license(
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    service = _get_service(request)
    return service.get_status()


@router.get("/license/features")
async def get_license_features(
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    gate = _get_gate(request)
    return {
        "edition": gate.current_edition().value,
        "status": gate.current_status().value,
        "features": sorted(gate.enabled_features()),
        "max_users": gate.max_users(),
        "max_organizations": gate.max_organizations(),
        "max_api_keys": gate.max_api_keys(),
    }


@router.get("/license/status")
async def get_license_status(
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    gate = _get_gate(request)
    return {
        "edition": gate.current_edition().value,
        "status": gate.current_status().value,
    }


@router.post("/license/activate", status_code=status.HTTP_201_CREATED)
async def activate_license(
    body: dict[str, Any],
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(require_admin),
) -> dict[str, Any]:
    service = _get_service(request)
    license_key = body.get("license_key", "").strip()
    if not license_key:
        raise HTTPException(status_code=400, detail="license_key is required")
    try:
        lic = service.activate(license_key, user_id=user.user_id)
    except InvalidLicenseKeyError as e:
        # Malformed key, or a signature that doesn't verify - a client
        # input problem, not a conflict with existing state. A specific
        # message here (not a generic 400/500) is the whole point: it's
        # what tells someone their key is garbage instead of leaving them
        # to guess.
        raise HTTPException(status_code=400, detail=str(e)) from None
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e)) from None
    return {"id": str(lic.id), "edition": lic.edition.value, "status": lic.status.value}


@router.post("/license/deactivate", status_code=status.HTTP_200_OK)
async def deactivate_license(
    body: dict[str, Any],
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(require_admin),
) -> dict[str, Any]:
    service = _get_service(request)
    license_id = body.get("license_id", "")
    if not license_id:
        raise HTTPException(status_code=400, detail="license_id is required")
    try:
        service.deactivate(license_id, user_id=user.user_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from None
    return {"status": "deactivated"}
