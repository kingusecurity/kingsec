"""FastAPI routes for MFA (TOTP) management and verification."""
from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from kingsec.application.errors import ApplicationError
from kingsec.application.use_cases.mfa_dto import (
    UseRecoveryCodeRequest,
    VerifyMfaCodeRequest,
)

from .auth import CurrentUser, get_current_user, require_admin
from .schemas import MfaStatusResponse as MfaStatusSchema

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1/mfa", tags=["mfa"])


def _get_app(request: Request) -> Application:
    return request.app.state.kingsec_app  # type: ignore[attr-defined]


@router.get(
    "/status",
    summary="Get MFA status",
    description="Check whether MFA is enabled for the authenticated user.",
    responses={
        200: {"description": "MFA status"},
        401: {"description": "Missing or invalid authentication"},
    },
)
async def get_mfa_status(
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
) -> MfaStatusSchema:
    from kingsec.application.use_cases.get_mfa_status import GetMfaStatus

    app = _get_app(request)
    use_case: GetMfaStatus = app.resolve(GetMfaStatus)
    result = use_case.execute(current_user.user_id)
    return MfaStatusSchema(enabled=result.enabled)


@router.post(
    "/enable",
    summary="Enable MFA (TOTP)",
    description="Generate a TOTP secret and provisioning URI for the authenticated user.",
    responses={
        200: {"description": "MFA enabled with TOTP secret and URI"},
        401: {"description": "Missing or invalid authentication"},
    },
)
async def enable_mfa(
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    from kingsec.application.use_cases.enable_mfa import EnableMfa
    from kingsec.application.use_cases.mfa_dto import EnableMfaRequest

    app = _get_app(request)
    use_case: EnableMfa = app.resolve(EnableMfa)
    result = use_case.execute(EnableMfaRequest(user_id=current_user.user_id))
    return {"secret": result.secret, "uri": result.uri}


@router.post(
    "/verify",
    summary="Authenticate with TOTP code",
    description=(
        "Authenticate using username, password, and TOTP code. "
        "Returns JWT tokens on success. Use this endpoint instead of "
        "/auth/login when MFA is enabled."
    ),
    responses={
        200: {"description": "Authentication successful"},
        401: {"description": "Invalid credentials or TOTP code"},
    },
)
async def verify_mfa(
    body: Annotated[dict, "VerifyMfaBody"],
    request: Request,
) -> dict:
    from kingsec.application.use_cases.verify_mfa_code import VerifyMfaCode

    app = _get_app(request)
    use_case: VerifyMfaCode = app.resolve(VerifyMfaCode)
    try:
        result = use_case.execute(VerifyMfaCodeRequest(
            username=body["username"],
            password=body["password"],
            totp_code=body["totp_code"],
        ))
    except ApplicationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    return {
        "user_id": result.user_id,
        "username": result.username,
        "role": result.role,
        "access_token": result.access_token,
        "refresh_token": result.refresh_token,
        "token_type": result.token_type,
        "expires_in": result.expires_in,
    }


@router.post(
    "/disable",
    summary="Disable MFA",
    description="Disable MFA for the authenticated user (user manages own MFA).",
    responses={
        200: {"description": "MFA disabled"},
        401: {"description": "Missing or invalid authentication"},
    },
)
async def disable_mfa(
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    from kingsec.application.use_cases.disable_mfa import DisableMfa
    from kingsec.application.use_cases.mfa_dto import DisableMfaRequest

    app = _get_app(request)
    use_case: DisableMfa = app.resolve(DisableMfa)
    use_case.execute(DisableMfaRequest(user_id=current_user.user_id))
    return {"status": "ok"}


@router.post(
    "/disable/{user_id}",
    summary="Admin: disable MFA for any user",
    description="ADMIN role required. Disable MFA for a specified user.",
    dependencies=[Depends(require_admin)],
    responses={
        200: {"description": "MFA disabled"},
        401: {"description": "Missing or invalid authentication"},
        403: {"description": "Insufficient permissions (ADMIN required)"},
    },
)
async def admin_disable_mfa(
    user_id: str,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    from kingsec.application.use_cases.disable_mfa import DisableMfa
    from kingsec.application.use_cases.mfa_dto import DisableMfaRequest

    app = _get_app(request)
    use_case: DisableMfa = app.resolve(DisableMfa)
    use_case.execute(DisableMfaRequest(user_id=user_id))
    return {"status": "ok"}


@router.post(
    "/recovery",
    summary="Authenticate with recovery code",
    description="Authenticate using username, password, and a recovery code (when MFA device is unavailable).",
    responses={
        200: {"description": "Authentication successful"},
        401: {"description": "Invalid credentials or recovery code"},
    },
)
async def use_recovery_code(
    body: Annotated[dict, "UseRecoveryCodeBody"],
    request: Request,
) -> dict:
    from kingsec.application.use_cases.use_recovery_code import UseRecoveryCode

    app = _get_app(request)
    use_case: UseRecoveryCode = app.resolve(UseRecoveryCode)
    try:
        result = use_case.execute(UseRecoveryCodeRequest(
            username=body["username"],
            password=body["password"],
            recovery_code=body["recovery_code"],
        ))
    except ApplicationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    return {
        "user_id": result.user_id,
        "username": result.username,
        "role": result.role,
        "access_token": result.access_token,
        "refresh_token": result.refresh_token,
        "token_type": result.token_type,
        "expires_in": result.expires_in,
    }


@router.post(
    "/recovery/generate",
    summary="Generate recovery codes",
    description="Generate initial recovery codes for MFA. Plaintext codes are returned once.",
    responses={
        200: {"description": "Recovery codes generated"},
        401: {"description": "Missing or invalid authentication"},
    },
)
async def generate_recovery_codes(
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    from kingsec.application.use_cases.generate_recovery_codes import GenerateRecoveryCodes
    from kingsec.application.use_cases.mfa_dto import GenerateRecoveryCodesRequest

    app = _get_app(request)
    use_case: GenerateRecoveryCodes = app.resolve(GenerateRecoveryCodes)
    result = use_case.execute(GenerateRecoveryCodesRequest(user_id=current_user.user_id))
    return {"codes": list(result.codes)}


@router.post(
    "/recovery/rotate",
    summary="Rotate recovery codes",
    description="Replace all existing recovery codes with new ones. Plaintext codes are returned once.",
    responses={
        200: {"description": "Recovery codes rotated"},
        401: {"description": "Missing or invalid authentication"},
    },
)
async def rotate_recovery_codes(
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    from kingsec.application.use_cases.mfa_dto import RotateRecoveryCodesRequest
    from kingsec.application.use_cases.rotate_recovery_codes import RotateRecoveryCodes

    app = _get_app(request)
    use_case: RotateRecoveryCodes = app.resolve(RotateRecoveryCodes)
    result = use_case.execute(RotateRecoveryCodesRequest(user_id=current_user.user_id))
    return {"codes": list(result.codes)}
