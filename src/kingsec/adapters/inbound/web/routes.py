"""FastAPI routes — the HTTP surface of KingSec.

Endpoints mirror the four ServiceAPI operations, plus a lightweight health
check. Each route:
    1. Accepts a Pydantic request body (validation at the boundary).
    2. Translates it to an application-layer DTO.
    3. Calls the corresponding ServiceAPI method.
    4. Returns a Pydantic response model (serialisation at the boundary).

Error handling is delegated to the exception handlers registered in
``error_handlers.py`` — routes contain no try/except blocks.

Security notes
    - All responses include ``Cache-Control: no-store`` to prevent sensitive
      data from being cached by intermediary proxies.
    - ``X-Content-Type-Options: nosniff`` is set on error responses to
      prevent MIME-type sniffing.
    - The health endpoint exposes no internal details.
    - Auth endpoints are public (no token required).
    - All other endpoints require a valid JWT Bearer token.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from kingsec.application.ports.inbound.service_api import ServiceAPI

from . import schemas

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

logger = logging.getLogger("kingsec.adapters.inbound.web.routes")
from kingsec.application.auth import Permission
from kingsec.domain import RateLimitGroup, Role

from .auth import (
    CurrentApiKey,
    CurrentUser,
    get_current_api_key,
    require_admin_jwt_only,
    require_analyst,
    require_permission,
    require_viewer,
    require_viewer_jwt_only,
)
from .dependencies import get_service
from .rate_limit_deps import require_rate_limit
from .session_helpers import create_session_for_login

router = APIRouter(prefix="/api/v1")


def _is_admin(user: CurrentUser) -> bool:
    return user.role == Role.ADMIN

# ── Health ───────────────────────────────────────────────────────────────────


@router.get(
    "/health",
    response_model=schemas.HealthResponse,
    tags=["health"],
    summary="Health check",
    description="Returns service health status. Exposes no internal details.",
)
async def health_check(request: Request) -> schemas.HealthResponse:
    # Phase 3 (auth hardening): the one public, unauthenticated signal
    # that no administrator exists yet - never internal details, just a
    # boolean an operator's monitoring (or the frontend) can act on
    # without needing to read source or hit /auth/register just to
    # provoke its 403.
    from kingsec.application.ports import UserRepository
    from kingsec.domain import Role

    app: Application = request.app.state.kingsec_app
    users: UserRepository = app.resolve(UserRepository)
    bootstrap_required = users.count_by_role(Role.ADMIN) == 0
    return schemas.HealthResponse(status="ok", bootstrap_required=bootstrap_required)


# ── Auth ─────────────────────────────────────────────────────────────────────


def _get_login_use_case(request: Request) -> Any:
    app: Application = request.app.state.kingsec_app
    from kingsec.application import Login

    return app.resolve(Login)


def _get_refresh_token_use_case(request: Request) -> Any:
    app: Application = request.app.state.kingsec_app
    from kingsec.application import RefreshToken

    return app.resolve(RefreshToken)


def _get_register_user_use_case(request: Request) -> Any:
    app: Application = request.app.state.kingsec_app
    from kingsec.application import RegisterUser

    return app.resolve(RegisterUser)


@router.post(
    "/auth/login",
    response_model=schemas.LoginResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Login",
    description="Authenticate with username and password. Returns access and refresh tokens.",
    responses={
        200: {"description": "Authentication successful"},
        401: {"description": "Invalid credentials"},
        429: {"description": "Rate limit exceeded"},
    },
)
async def login(
    body: schemas.LoginBody,
    request: Request,
    login_uc: Any = Depends(_get_login_use_case),
    _rate_limit: None = Depends(require_rate_limit(RateLimitGroup.LOGIN)),
) -> schemas.LoginResponse:
    from kingsec.application.dto import LoginRequest
    from kingsec.application.use_cases.login import AuthenticationError

    login_request = LoginRequest(username=body.username, password=body.password)
    try:
        result = login_uc.execute(login_request)
    except AuthenticationError:
        _record_failed_login_audit(request, body.username)
        raise

    # MFA still required: no real tokens exist yet, so there is nothing to
    # create a session for. The session is created when the login is
    # actually completed via /mfa/verify or /mfa/recovery instead.
    if not result.mfa_required and result.access_token is not None and result.refresh_token is not None:
        create_session_for_login(
            request,
            user_id=result.user_id,
            access_token=result.access_token,
            refresh_token=result.refresh_token,
        )

    return schemas.LoginResponse(
        user_id=result.user_id,
        username=result.username,
        role=result.role,
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        mfa_required=result.mfa_required,
        pending_token=result.pending_token,
        token_type=result.token_type,
        expires_in=result.expires_in,
    )


def _record_failed_login_audit(request: Request, username: str) -> None:
    """Record a failed login audit entry at the web boundary (best-effort)."""
    try:
        app: Application = request.app.state.kingsec_app
        from kingsec.application.ports import AuditPublisher
        from kingsec.domain.audit import AuditAction, AuditEntry

        audit = app.resolve(AuditPublisher)
        ip = getattr(request.state, "audit_ip", "") or ""
        user_agent = getattr(request.state, "audit_user_agent", "") or ""
        correlation_id = getattr(request.state, "audit_correlation_id", "") or ""

        audit.record(
            AuditEntry(
                action=AuditAction.FAILED_LOGIN,
                resource_type="user",
                success=False,
                reason="invalid username or password",
                username=username,
                ip_address=ip,
                user_agent=user_agent,
                correlation_id=correlation_id,
            )
        )
    except Exception:
        logger.warning("Failed to record failed login audit", exc_info=True)


@router.post(
    "/auth/refresh",
    response_model=schemas.RefreshTokenResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Refresh access token",
    description="Exchange a valid refresh token for a new access token.",
    responses={
        200: {"description": "Token refreshed successfully"},
        401: {"description": "Invalid or expired refresh token"},
    },
)
async def refresh_token(
    body: schemas.RefreshTokenBody,
    refresh_uc: Any = Depends(_get_refresh_token_use_case),
    _rate_limit: None = Depends(require_rate_limit(RateLimitGroup.REFRESH_TOKEN)),
) -> schemas.RefreshTokenResponse:
    from kingsec.application.dto import RefreshTokenRequest

    request = RefreshTokenRequest(refresh_token=body.refresh_token)
    result = refresh_uc.execute(request)
    return schemas.RefreshTokenResponse(
        access_token=result.access_token,
        token_type=result.token_type,
        expires_in=result.expires_in,
    )


@router.post(
    "/auth/register",
    response_model=schemas.RegisterUserResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["auth"],
    summary="Register new user",
    description="Create a new user account. Default role is Viewer.",
    responses={
        201: {"description": "User registered successfully"},
        400: {"description": "Validation error or duplicate username/email"},
    },
)
async def register_user(
    body: schemas.RegisterUserBody,
    register_uc: Any = Depends(_get_register_user_use_case),
) -> schemas.RegisterUserResponse:
    from kingsec.application.dto import RegisterUserRequest

    request = RegisterUserRequest(
        username=body.username,
        email=body.email,
        password=body.password,
    )
    result = register_uc.execute(request)
    return schemas.RegisterUserResponse(
        user_id=result.user_id,
        username=result.username,
        email=result.email,
        role=result.role,
    )


def _get_assign_role_use_case(request: Request) -> Any:
    app: Application = request.app.state.kingsec_app
    from kingsec.application.use_cases.assign_role import AssignRole

    return app.resolve(AssignRole)


@router.get(
    "/auth/me",
    response_model=schemas.UserResponse,
    tags=["auth"],
    summary="Get current user",
    description="Returns the authenticated user's profile.",
    responses={
        200: {"description": "User profile"},
        401: {"description": "Missing or invalid token"},
    },
)
async def get_current_user_info(
    current_user: CurrentUser = Depends(require_viewer),
    request: Request = None,  # type: ignore[assignment]
) -> schemas.UserResponse:
    """Return the current authenticated user's profile."""
    app: Application = request.app.state.kingsec_app
    from kingsec.application import UserRepository

    user_repo = app.resolve(UserRepository)
    user = user_repo.find_by_id(current_user.user_id)

    if user is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="user not found")

    return schemas.UserResponse(
        user_id=user.id,
        username=user.username,
        email=user.email,
        role=user.role.label,
        is_active=user.is_active,
        created_at=user.created_at.isoformat(),
        last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
    )


@router.post(
    "/auth/change-password",
    tags=["auth"],
    summary="Change own password",
    description="Change the authenticated user's own password.",
    responses={
        200: {"description": "Password changed"},
        400: {"description": "Current password incorrect or new password invalid"},
        401: {"description": "Missing or invalid token"},
    },
)
async def change_own_password(
    body: schemas.ChangePasswordBody,
    current_user: CurrentUser = Depends(require_viewer_jwt_only),
    request: Request = None,  # type: ignore[assignment]
) -> dict[str, str]:
    app: Application = request.app.state.kingsec_app
    from kingsec.application.dto import ChangePasswordRequest
    from kingsec.application.use_cases.change_password import ChangePassword, PasswordChangeError

    change_uc = app.resolve(ChangePassword)
    try:
        change_uc.execute(
            ChangePasswordRequest(
                user_id=current_user.user_id,
                current_password=body.current_password,
                new_password=body.new_password,
            )
        )
    except PasswordChangeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {"message": "Password changed successfully"}


# ── List Assessments ─────────────────────────────────────────────────────────


@router.get(
    "/assessments",
    response_model=schemas.ListAssessmentsResponse,
    tags=["assessments"],
    dependencies=[Depends(require_viewer)],
    summary="List assessments",
    description="Returns a paginated list of assessments.",
    responses={
        200: {"description": "List of assessments"},
        401: {"description": "Missing or invalid token"},
    },
)
async def list_assessments(
    limit: int = 50,
    offset: int = 0,
    current_user: CurrentUser = Depends(require_viewer),
    service: ServiceAPI = Depends(get_service),
) -> schemas.ListAssessmentsResponse:
    from kingsec.application.dto import ListAssessmentsRequest

    limit = max(1, min(limit, 200))
    request = ListAssessmentsRequest(
        limit=limit,
        offset=offset,
        requesting_user=current_user.user_id,
        is_admin=_is_admin(current_user),
    )
    result = service.list_assessments(request)
    return schemas.ListAssessmentsResponse(
        items=[
            schemas.AssessmentSummaryResponse(
                assessment_id=item.assessment_id,
                target=item.target,
                status=item.status,
                is_authorized=item.is_authorized,
                created_at=item.created_at,
                findings_count=item.findings_count,
            )
            for item in result.items
        ],
        total=result.total,
        limit=result.limit,
        offset=result.offset,
        unreadable_ids=list(result.unreadable_ids),
    )


# ── Create Assessment ────────────────────────────────────────────────────────


@router.post(
    "/assessments",
    response_model=schemas.CreateAssessmentResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["assessments"],
    dependencies=[Depends(require_analyst)],
    summary="Create assessment",
    description="Create and authorize a new assessment. Requires Analyst role.",
    responses={
        201: {"description": "Assessment created"},
        400: {"description": "Validation error"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions"},
    },
)
async def create_assessment(
    body: schemas.CreateAssessmentBody,
    current_user: CurrentUser = Depends(require_analyst),
    service: ServiceAPI = Depends(get_service),
) -> schemas.CreateAssessmentResponse:
    from kingsec.application.dto import CreateAssessmentRequest

    request = CreateAssessmentRequest(
        target_value=body.target_value,
        target_type=body.target_type,
        authorized_by=body.authorized_by,
        scope=body.scope,
        owner_id=current_user.user_id,
        requesting_username=current_user.username,
        profile_id=body.profile_id,
        requesting_is_admin=_is_admin(current_user),
        override_scope_check=body.override_scope_check,
    )
    result = service.create_assessment(request)
    return schemas.CreateAssessmentResponse(
        assessment_id=result.assessment_id,
        status=result.status,
        target=result.target,
    )


# ── Start Assessment (submits for background execution) ───────────────────────


@router.post(
    "/assessments/{assessment_id}/start",
    response_model=schemas.StartAssessmentResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["assessments"],
    dependencies=[Depends(require_analyst)],
    summary="Start assessment",
    description="Submit an authorized assessment for background scanning. Returns 202 Accepted.",
    responses={
        202: {"description": "Assessment submitted for execution"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Assessment not found"},
    },
)
async def start_assessment(
    assessment_id: str,
    _body: schemas.StartAssessmentBody | None = None,
    current_user: CurrentUser = Depends(require_analyst),
    service: ServiceAPI = Depends(get_service),
) -> schemas.StartAssessmentResponse:
    from kingsec.application.dto import SubmitAssessmentRequest

    request = SubmitAssessmentRequest(
        assessment_id=assessment_id,
        requesting_user=current_user.user_id,
        requesting_username=current_user.username,
        is_admin=_is_admin(current_user),
    )
    result = service.submit_assessment(request)
    return schemas.StartAssessmentResponse(
        assessment_id=result.assessment_id,
        status=result.status,
        job_id=result.job_id,
    )


# ── Get Assessment ───────────────────────────────────────────────────────────


@router.get(
    "/assessments/{assessment_id}",
    response_model=schemas.AssessmentResponse,
    tags=["assessments"],
    dependencies=[Depends(require_viewer)],
    summary="Get assessment",
    description="Returns full assessment details including findings.",
    responses={
        200: {"description": "Assessment details"},
        401: {"description": "Missing or invalid token"},
        404: {"description": "Assessment not found"},
    },
)
async def get_assessment(
    assessment_id: str,
    current_user: CurrentUser = Depends(require_viewer),
    service: ServiceAPI = Depends(get_service),
) -> schemas.AssessmentResponse:
    from kingsec.application.dto import GetAssessmentRequest

    request = GetAssessmentRequest(
        assessment_id=assessment_id,
        requesting_user=current_user.user_id,
        is_admin=_is_admin(current_user),
    )
    result = service.get_assessment(request)
    return schemas.AssessmentResponse(
        assessment_id=result.assessment_id,
        target=result.target,
        status=result.status,
        is_authorized=result.is_authorized,
        created_at=result.created_at,
        findings=[
            schemas.FindingResponse(
                finding_id=f.finding_id,
                title=f.title,
                severity=f.severity,
                status=f.status,
                evidence_count=f.evidence_count,
                recommendation_count=f.recommendation_count,
                affected_asset=f.affected_asset,
            )
            for f in result.findings
        ],
        profile_id=result.profile_id,
        scanner_summary=[
            schemas.ScannerSummaryResponse(
                scanner_id=s.scanner_id,
                name=s.name,
                status=s.status,
                findings_count=s.findings_count,
                skipped_reason=s.skipped_reason,
            )
            for s in result.scanner_summary
        ],
        failure_reason=result.failure_reason,
    )


# ── Generate Report ──────────────────────────────────────────────────────────


@router.post(
    "/assessments/{assessment_id}/report",
    response_model=schemas.GenerateReportResponse,
    tags=["assessments"],
    dependencies=[Depends(require_analyst)],
    summary="Generate report",
    description="Generate a PDF report for a completed assessment.",
    responses={
        200: {"description": "Report generated"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Assessment not found"},
    },
)
async def generate_report(
    assessment_id: str,
    _body: schemas.GenerateReportBody | None = None,
    current_user: CurrentUser = Depends(require_analyst),
    service: ServiceAPI = Depends(get_service),
) -> schemas.GenerateReportResponse:
    from kingsec.application.dto import GenerateReportRequest

    request = GenerateReportRequest(
        assessment_id=assessment_id,
        requesting_user=current_user.user_id,
        requesting_username=current_user.username,
        is_admin=_is_admin(current_user),
    )
    # Phase 2B-c Priority 2 (5c): report generation renders a PDF/HTML
    # artifact synchronously (WeasyPrint) - offload to a thread so a large
    # report never blocks the event loop for every other request in flight.
    result = await asyncio.to_thread(service.generate_report, request)
    return schemas.GenerateReportResponse(
        assessment_id=result.assessment_id,
        verdict=result.verdict,
        action_required=result.action_required,
        highest_severity=result.highest_severity,
        total_findings=result.total_findings,
        severity_counts=[
            schemas.SeverityCountResponse(severity=s.severity, count=s.count) for s in result.severity_counts
        ],
        artifact_media_type=result.artifact_media_type,
        artifact_filename=result.artifact_filename,
        artifact_bytes=result.artifact_bytes,
    )


# ── Cancel Assessment ────────────────────────────────────────────────────────


@router.post(
    "/assessments/{assessment_id}/cancel",
    response_model=schemas.CancelAssessmentResponse,
    status_code=status.HTTP_200_OK,
    tags=["assessments"],
    dependencies=[Depends(require_analyst)],
    summary="Cancel assessment",
    description="Cancel a running or authorized assessment.",
    responses={
        200: {"description": "Assessment cancelled"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Assessment not found"},
    },
)
async def cancel_assessment(
    assessment_id: str,
    _body: schemas.CancelAssessmentBody | None = None,
    current_user: CurrentUser = Depends(require_analyst),
    service: ServiceAPI = Depends(get_service),
) -> schemas.CancelAssessmentResponse:
    from kingsec.application.dto import CancelAssessmentRequest

    request = CancelAssessmentRequest(
        assessment_id=assessment_id,
        requesting_user=current_user.user_id,
        requesting_username=current_user.username,
        is_admin=_is_admin(current_user),
    )
    result = service.cancel_assessment(request)
    return schemas.CancelAssessmentResponse(
        assessment_id=result.assessment_id,
        status=result.status,
    )


# ── Delete Assessment ────────────────────────────────────────────────────────


@router.delete(
    "/assessments/{assessment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["assessments"],
    dependencies=[Depends(require_analyst)],
    summary="Delete assessment",
    description="Permanently delete an assessment and all its findings.",
    responses={
        204: {"description": "Assessment deleted"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Assessment not found"},
    },
)
async def delete_assessment(
    assessment_id: str,
    current_user: CurrentUser = Depends(require_analyst),
    service: ServiceAPI = Depends(get_service),
) -> None:
    from kingsec.application.dto import DeleteAssessmentRequest

    request = DeleteAssessmentRequest(
        assessment_id=assessment_id,
        requesting_user=current_user.user_id,
        requesting_username=current_user.username,
        is_admin=_is_admin(current_user),
    )
    service.delete_assessment(request)


# ── API Keys ──────────────────────────────────────────────────────────────────


def _get_create_api_key_uc(request: Request) -> Any:
    app: Application = request.app.state.kingsec_app
    from kingsec.application import CreateApiKey

    return app.resolve(CreateApiKey)


def _get_list_api_keys_uc(request: Request) -> Any:
    app: Application = request.app.state.kingsec_app
    from kingsec.application import ListApiKeys

    return app.resolve(ListApiKeys)


def _get_revoke_api_key_uc(request: Request) -> Any:
    app: Application = request.app.state.kingsec_app
    from kingsec.application import RevokeApiKey

    return app.resolve(RevokeApiKey)


def _get_rotate_api_key_uc(request: Request) -> Any:
    app: Application = request.app.state.kingsec_app
    from kingsec.application import RotateApiKey

    return app.resolve(RotateApiKey)


@router.post(
    "/apikeys",
    response_model=schemas.CreateApiKeyResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["api-keys"],
    summary="Create API key",
    description="Create a new API key. The plaintext key is returned once.",
    responses={
        201: {"description": "API key created"},
        400: {"description": "Validation error"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions"},
    },
)
async def create_api_key(
    body: schemas.CreateApiKeyBody,
    current_user: CurrentUser = Depends(require_permission(Permission.CREATE_API_KEY, jwt_only=True)),
    create_uc: Any = Depends(_get_create_api_key_uc),
) -> schemas.CreateApiKeyResponse:
    from kingsec.application.dto import CreateApiKeyRequest

    request = CreateApiKeyRequest(
        user_id=current_user.user_id,
        name=body.name,
        scope=body.scope,
    )
    result = create_uc.execute(request)
    return schemas.CreateApiKeyResponse(
        api_key_id=result.api_key_id,
        name=result.name,
        plaintext_key=result.plaintext_key,
        scope=result.scope,
        created_at=result.created_at,
    )


@router.get(
    "/apikeys",
    response_model=schemas.ApiKeyListResponse,
    tags=["api-keys"],
    summary="List API keys",
    description="List API keys for the current user.",
    responses={
        200: {"description": "List of API keys"},
        401: {"description": "Missing or invalid token"},
    },
)
async def list_api_keys(
    limit: int = 50,
    offset: int = 0,
    current_user: CurrentUser = Depends(require_permission(Permission.LIST_API_KEYS, jwt_only=True)),
    list_uc: Any = Depends(_get_list_api_keys_uc),
) -> schemas.ApiKeyListResponse:
    from kingsec.application.dto import ListApiKeysRequest

    limit = max(1, min(limit, 200))
    request = ListApiKeysRequest(
        user_id=current_user.user_id,
        limit=limit,
        offset=offset,
    )
    items = list_uc.execute(request)
    total = list_uc.count(request)
    return schemas.ApiKeyListResponse(
        items=[
            schemas.ApiKeyResponse(
                api_key_id=item.api_key_id,
                user_id=item.user_id,
                name=item.name,
                scope=item.scope,
                status=item.status,
                last_used_at=item.last_used_at,
                created_at=item.created_at,
            )
            for item in items
        ],
        total=total,
        limit=request.limit,
        offset=request.offset,
    )


@router.get(
    "/apikeys/me",
    response_model=schemas.CurrentApiKeyResponse,
    tags=["api-keys"],
    summary="Get current API key info",
    description="Returns information about the API key used for authentication.",
    responses={
        200: {"description": "API key info"},
        401: {"description": "Missing or invalid API key"},
    },
)
async def get_current_api_key_info(
    current_api_key: CurrentApiKey = Depends(get_current_api_key),
    request: Request = None,  # type: ignore[assignment]
) -> schemas.CurrentApiKeyResponse:
    from kingsec.application.ports import ApiKeyRepository

    app: Application = request.app.state.kingsec_app
    repo = app.resolve(ApiKeyRepository)
    key = repo.find_by_id(current_api_key.api_key_id)

    return schemas.CurrentApiKeyResponse(
        api_key_id=current_api_key.api_key_id,
        user_id=current_api_key.user_id,
        name=key.name if key else "",
        scope=current_api_key.scope,
        status=current_api_key.status,
        last_used_at=key.last_used_at.isoformat() if key and key.last_used_at else None,
        created_at=key.created_at.isoformat() if key else "",
    )


@router.delete(
    "/apikeys/{api_key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["api-keys"],
    summary="Revoke API key",
    description="Revoke an API key by its ID.",
    responses={
        204: {"description": "API key revoked"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions or not the owner"},
        404: {"description": "API key not found"},
    },
)
async def revoke_api_key(
    api_key_id: str,
    current_user: CurrentUser = Depends(require_permission(Permission.DELETE_API_KEY, jwt_only=True)),
    revoke_uc: Any = Depends(_get_revoke_api_key_uc),
) -> None:
    from kingsec.application.dto import RevokeApiKeyRequest

    request = RevokeApiKeyRequest(
        api_key_id=api_key_id,
        requesting_user_id=current_user.user_id,
    )
    revoke_uc.execute(request)


@router.post(
    "/apikeys/{api_key_id}/rotate",
    response_model=schemas.RotateApiKeyResponse,
    tags=["api-keys"],
    summary="Rotate API key",
    description="Rotate an API key — generates a new key and invalidates the old one.",
    responses={
        200: {"description": "API key rotated"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions or not the owner"},
        404: {"description": "API key not found"},
    },
)
async def rotate_api_key(
    api_key_id: str,
    current_user: CurrentUser = Depends(require_permission(Permission.ROTATE_API_KEY, jwt_only=True)),
    rotate_uc: Any = Depends(_get_rotate_api_key_uc),
) -> schemas.RotateApiKeyResponse:
    from kingsec.application.dto import RotateApiKeyRequest

    request = RotateApiKeyRequest(
        api_key_id=api_key_id,
        requesting_user_id=current_user.user_id,
    )
    result = rotate_uc.execute(request)
    return schemas.RotateApiKeyResponse(
        api_key_id=result.api_key_id,
        name=result.name,
        plaintext_key=result.plaintext_key,
        scope=result.scope,
        created_at=result.created_at,
    )


@router.get(
    "/users",
    response_model=schemas.ListUsersResponse,
    tags=["auth"],
    dependencies=[Depends(require_admin_jwt_only)],
    summary="List users",
    description="Returns a paginated list of users. Requires Admin role.",
    responses={
        200: {"description": "List of users"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions"},
    },
)
async def list_users(
    limit: int = 50,
    offset: int = 0,
    request: Request = None,  # type: ignore[assignment]
) -> schemas.ListUsersResponse:
    app: Application = request.app.state.kingsec_app
    from kingsec.application import UserRepository

    limit = max(1, min(limit, 200))
    user_repo = app.resolve(UserRepository)
    users = user_repo.list_all(limit=limit, offset=offset)
    total = user_repo.count()
    return schemas.ListUsersResponse(
        items=[
            schemas.UserListEntryResponse(
                user_id=u.id,
                username=u.username,
                email=u.email,
                role=u.role.name,
                is_active=u.is_active,
                created_at=u.created_at.isoformat(),
                last_login_at=u.last_login_at.isoformat() if u.last_login_at else None,
            )
            for u in users
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.put(
    "/users/{user_id}/role",
    response_model=schemas.AssignRoleResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
    summary="Assign role to user",
    description="Change a user's role. Requires Admin role. Cannot demote the last admin.",
    responses={
        200: {"description": "Role assigned"},
        400: {"description": "Invalid role or cannot demote last admin"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "User not found"},
    },
)
async def assign_role(
    user_id: str,
    body: schemas.AssignRoleBody,
    current_user: CurrentUser = Depends(require_admin_jwt_only),
    assign_role_uc: Any = Depends(_get_assign_role_use_case),
) -> schemas.AssignRoleResponse:
    from kingsec.application.dto import AssignRoleRequest
    from kingsec.application.use_cases.assign_role import AssignRoleError

    request = AssignRoleRequest(
        requesting_user_id=current_user.user_id,
        target_user_id=user_id,
        new_role=body.role,
    )
    try:
        result = assign_role_uc.execute(request)
    except AssignRoleError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return schemas.AssignRoleResponse(
        user_id=result.user_id,
        username=result.username,
        email=result.email,
        new_role=result.new_role,
    )


# ── Findings ──────────────────────────────────────────────────────────────────


def _get_list_findings_uc(request: Request) -> Any:
    app: Application = request.app.state.kingsec_app
    from kingsec.application.use_cases.list_findings import ListFindings

    return app.resolve(ListFindings)


@router.get(
    "/findings",
    response_model=schemas.ListFindingsResponse,
    tags=["findings"],
    dependencies=[Depends(require_viewer)],
    summary="List findings",
    description="Returns paginated findings with optional filters.",
)
async def list_findings(
    limit: int = 50,
    offset: int = 0,
    severity: str | None = None,
    status: str | None = None,
    assessment_id: str | None = None,
    search: str | None = None,
    order_by: str = "discovered_at",
    order_dir: str = "desc",
    current_user: CurrentUser = Depends(require_viewer),
    list_uc: Any = Depends(_get_list_findings_uc),
) -> schemas.ListFindingsResponse:
    from kingsec.application.use_cases.list_findings import ListFindingsRequest

    limit = max(1, min(limit, 200))
    request = ListFindingsRequest(
        limit=limit,
        offset=offset,
        severity=severity,
        status=status,
        assessment_id=assessment_id,
        search=search,
        order_by=order_by,
        order_dir=order_dir,
        requesting_user=current_user.user_id,
        is_admin=_is_admin(current_user),
    )
    result = list_uc.execute(request)
    return schemas.ListFindingsResponse(
        items=[
            schemas.FindingListEntryResponse(
                finding_id=item.finding_id,
                assessment_id=item.assessment_id,
                target=item.target,
                title=item.title,
                description=item.description,
                severity=item.severity,
                status=item.status,
                discovered_at=item.discovered_at,
                evidence_count=item.evidence_count,
                recommendation_count=item.recommendation_count,
            )
            for item in result.items
        ],
        total=result.total,
        limit=result.limit,
        offset=result.offset,
    )


# ── Reports ───────────────────────────────────────────────────────────────────


def _refuse_stale_report_if_assessment_now_failed(assessment: Any) -> None:
    """Phase 2C Step 2, GAP-1 follow-up: the same refusal
    Report.from_assessment() applies at GENERATION time must also apply on
    the READ path.

    A report is a snapshot, and Phase 2B-c Priority 2's report cache means
    /reports/{id}/download can serve a STORED artifact without ever calling
    from_assessment() again - a report generated before derive_assessment_status()
    existed can still be sitting in the database with a stale
    assessment_status, and both the JSON metadata endpoint (get_report) and
    the download endpoint (download_report) read that stored row directly,
    bypassing generation-time's own refusal entirely. Re-checking the
    assessment's CURRENT derived status here, before either endpoint reads
    the stored report, closes that gap: a report whose assessment now
    derives to FAILED is refused with the same IllegalStateTransition
    Report.from_assessment() itself would raise - never served from cache.
    """
    from kingsec.domain.enums import AssessmentStatus
    from kingsec.domain.errors import IllegalStateTransition
    from kingsec.domain.report import derive_assessment_status

    derived_status = derive_assessment_status(assessment)
    if derived_status is AssessmentStatus.FAILED:
        raise IllegalStateTransition(
            "no report can be generated: every scanner failed to complete for this "
            "assessment, so no assessment data was collected",
            current=derived_status,
        )


def _get_list_reports_uc(request: Request) -> Any:
    app: Application = request.app.state.kingsec_app
    from kingsec.application.use_cases.list_reports import ListReports

    return app.resolve(ListReports)


@router.get(
    "/reports",
    response_model=schemas.ListReportsResponse,
    tags=["reports"],
    dependencies=[Depends(require_viewer)],
    summary="List reports",
    description="Returns paginated list of generated reports with search, filter, and sort.",
)
async def list_reports(
    limit: int = 50,
    offset: int = 0,
    order_by: str = "generated_at",
    order_dir: str = "desc",
    search: str | None = None,
    severity: str | None = None,
    target: str | None = None,
    current_user: CurrentUser = Depends(require_viewer),
    list_uc: Any = Depends(_get_list_reports_uc),
) -> schemas.ListReportsResponse:
    from kingsec.application.use_cases.list_reports import ListReportsRequest

    limit = max(1, min(limit, 200))
    request = ListReportsRequest(
        limit=limit,
        offset=offset,
        order_by=order_by,
        order_dir=order_dir,
        search=search,
        severity=severity,
        target=target,
        requesting_user=current_user.user_id,
        is_admin=_is_admin(current_user),
    )
    result = list_uc.execute(request)
    return schemas.ListReportsResponse(
        items=[
            schemas.ReportListEntryResponse(
                assessment_id=item.assessment_id,
                target=item.target,
                generated_at=item.generated_at,
                verdict_headline=item.verdict_headline,
                verdict_highest_severity=item.verdict_highest_severity,
                verdict_action_required=item.verdict_action_required,
                total_findings=item.total_findings,
                critical_count=item.critical_count,
                high_count=item.high_count,
                medium_count=item.medium_count,
                low_count=item.low_count,
                info_count=item.info_count,
                executive_score=item.executive_score,
                format=item.format,
                file_size=item.file_size,
            )
            for item in result.items
        ],
        total=result.total,
        limit=result.limit,
        offset=result.offset,
    )


@router.get(
    "/reports/{assessment_id}",
    tags=["reports"],
    dependencies=[Depends(require_viewer)],
    summary="Get report metadata",
    description="Returns enriched metadata for a specific report.",
)
async def get_report(
    assessment_id: str,
    current_user: CurrentUser = Depends(require_viewer),
    request: Request = None,  # type: ignore[assignment]
) -> schemas.ReportDetailResponse:
    app: Application = request.app.state.kingsec_app
    from kingsec.application._support import check_assessment_access
    from kingsec.application.ports import AssessmentRepository, ReportRepository
    from kingsec.domain import AssessmentId, Severity

    assessments: AssessmentRepository = app.resolve(AssessmentRepository)
    assessment = assessments.get(AssessmentId(assessment_id))
    check_assessment_access(assessment, current_user.user_id, _is_admin(current_user))
    _refuse_stale_report_if_assessment_now_failed(assessment)

    repo: ReportRepository = app.resolve(ReportRepository)
    report = repo.get(AssessmentId(assessment_id))
    sc = {s.name: report.count_for(s) for s in Severity}
    return schemas.ReportDetailResponse(
        assessment_id=report.assessment_id,
        target=report.target,
        generated_at=report.generated_at.isoformat(),
        verdict_headline=report.verdict.headline,
        verdict_highest_severity=report.verdict.highest_severity.name if report.verdict.highest_severity else None,
        verdict_action_required=report.verdict.action_required,
        total_findings=report.total_findings,
        critical_count=sc.get("CRITICAL", 0),
        high_count=sc.get("HIGH", 0),
        medium_count=sc.get("MEDIUM", 0),
        low_count=sc.get("LOW", 0),
        info_count=sc.get("INFORMATIONAL", 0),
        executive_score=report.executive_score,
        format="pdf",
        file_size=0,
    )


@router.get(
    "/reports/{assessment_id}/download",
    tags=["reports"],
    dependencies=[Depends(require_viewer)],
    summary="Download report",
    description="Download a generated report as PDF (default) or HTML via ?format=html.",
)
async def download_report(
    assessment_id: str,
    format: str | None = None,
    current_user: CurrentUser = Depends(require_viewer),
    request: Request = None,  # type: ignore[assignment]
) -> Any:
    app: Application = request.app.state.kingsec_app
    from kingsec.application._support import check_assessment_access
    from kingsec.application.ports import AssessmentRepository, ReportGeneratorPort, ReportRepository
    from kingsec.domain import AssessmentId

    if format is not None and format.lower() not in ("pdf", "html"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unsupported report format {format!r}; supported: html, pdf",
        )

    assessments: AssessmentRepository = app.resolve(AssessmentRepository)
    assessment = assessments.get(AssessmentId(assessment_id))
    check_assessment_access(assessment, current_user.user_id, _is_admin(current_user))
    _refuse_stale_report_if_assessment_now_failed(assessment)

    repo: ReportRepository = app.resolve(ReportRepository)
    generator: ReportGeneratorPort = app.resolve(ReportGeneratorPort)
    report = repo.get(AssessmentId(assessment_id))
    # Phase 2B-c Priority 2 (5c): same offload as generate_report() above -
    # render() is a blocking WeasyPrint call (5d also makes this a cheap
    # cache read on repeat calls, but the first render for a given report
    # still pays the full cost and must not block the event loop).
    rendered = await asyncio.to_thread(generator.render, report, format=format)
    from fastapi.responses import Response

    return Response(
        content=rendered.content,
        media_type=rendered.media_type,
        headers={"Content-Disposition": f'attachment; filename="{rendered.filename}"'},
    )


# ── User Administration ───────────────────────────────────────────────────────


def _get_deactivate_user_uc(request: Request) -> Any:
    app: Application = request.app.state.kingsec_app
    from kingsec.application.use_cases.admin_users import DeactivateUser

    return app.resolve(DeactivateUser)


def _get_activate_user_uc(request: Request) -> Any:
    app: Application = request.app.state.kingsec_app
    from kingsec.application.use_cases.admin_users import ActivateUser

    return app.resolve(ActivateUser)


def _get_reset_password_uc(request: Request) -> Any:
    app: Application = request.app.state.kingsec_app
    from kingsec.application.use_cases.admin_users import AdminResetPassword

    return app.resolve(AdminResetPassword)


@router.patch(
    "/users/{user_id}/deactivate",
    response_model=schemas.AdminUserActionResponse,
    tags=["auth"],
    dependencies=[Depends(require_admin_jwt_only)],
    summary="Deactivate user",
    description="Deactivate a user account. Requires Admin role.",
)
async def deactivate_user(
    user_id: str,
    current_user: CurrentUser = Depends(require_admin_jwt_only),
    deactivate_uc: Any = Depends(_get_deactivate_user_uc),
) -> schemas.AdminUserActionResponse:
    from kingsec.application.use_cases.admin_users import DeactivateUserRequest

    request = DeactivateUserRequest(
        user_id=user_id, admin_user_id=current_user.user_id, admin_username=current_user.username
    )
    result = deactivate_uc.execute(request)
    return schemas.AdminUserActionResponse(
        user_id=result.user_id,
        username=result.username,
        email=result.email,
        role=result.role,
        is_active=result.is_active,
    )


@router.patch(
    "/users/{user_id}/activate",
    response_model=schemas.AdminUserActionResponse,
    tags=["auth"],
    dependencies=[Depends(require_admin_jwt_only)],
    summary="Activate user",
    description="Activate a deactivated user account. Requires Admin role.",
)
async def activate_user(
    user_id: str,
    current_user: CurrentUser = Depends(require_admin_jwt_only),
    activate_uc: Any = Depends(_get_activate_user_uc),
) -> schemas.AdminUserActionResponse:
    from kingsec.application.use_cases.admin_users import ActivateUserRequest

    request = ActivateUserRequest(
        user_id=user_id, admin_user_id=current_user.user_id, admin_username=current_user.username
    )
    result = activate_uc.execute(request)
    return schemas.AdminUserActionResponse(
        user_id=result.user_id,
        username=result.username,
        email=result.email,
        role=result.role,
        is_active=result.is_active,
    )


@router.post(
    "/users/{user_id}/reset-password",
    response_model=schemas.AdminUserActionResponse,
    tags=["auth"],
    dependencies=[Depends(require_admin_jwt_only)],
    summary="Reset user password",
    description="Reset another user's password. Requires Admin role.",
)
async def reset_password(
    user_id: str,
    body: schemas.AdminResetPasswordBody,
    current_user: CurrentUser = Depends(require_admin_jwt_only),
    reset_uc: Any = Depends(_get_reset_password_uc),
) -> schemas.AdminUserActionResponse:
    from kingsec.application.use_cases.admin_users import ResetPasswordRequest

    request = ResetPasswordRequest(
        user_id=user_id,
        new_password=body.new_password,
        admin_user_id=current_user.user_id,
        admin_username=current_user.username,
    )
    result = reset_uc.execute(request)
    return schemas.AdminUserActionResponse(
        user_id=result.user_id,
        username=result.username,
        email=result.email,
        role=result.role,
        is_active=result.is_active,
    )


@router.get(
    "/users/search",
    response_model=schemas.ListUsersResponse,
    tags=["auth"],
    dependencies=[Depends(require_admin_jwt_only)],
    summary="Search users",
    description="Search users with filters. Requires Admin role.",
)
async def search_users(
    query: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
    limit: int = 50,
    offset: int = 0,
    order_by: str = "username",
    order_dir: str = "asc",
    request: Request = None,  # type: ignore[assignment]
) -> schemas.ListUsersResponse:
    from kingsec.application.use_cases.admin_users import SearchUsers, SearchUsersRequest

    limit = max(1, min(limit, 200))
    app: Application = request.app.state.kingsec_app
    search_uc: SearchUsers = app.resolve(SearchUsers)
    req = SearchUsersRequest(
        query=query,
        role=role,
        is_active=is_active,
        limit=limit,
        offset=offset,
        order_by=order_by,
        order_dir=order_dir,
    )
    result = search_uc.execute(req)
    return schemas.ListUsersResponse(
        items=[
            schemas.UserListEntryResponse(
                user_id=item.user_id,
                username=item.username,
                email=item.email,
                role=item.role,
                is_active=item.is_active,
                created_at=item.created_at,
                last_login_at=item.last_login_at,
            )
            for item in result.items
        ],
        total=result.total,
        limit=result.limit,
        offset=result.offset,
    )


# ── Roles & Permissions ────────────────────────────────────────────────────────


@router.get(
    "/roles",
    response_model=schemas.ListRolesResponse,
    tags=["auth"],
    dependencies=[Depends(require_admin_jwt_only)],
    summary="List roles",
    description="Return all roles with their descriptions and permissions.",
)
async def list_roles(
    request: Request = None,  # type: ignore[assignment]
) -> schemas.ListRolesResponse:
    from kingsec.application.auth.authorization_service import AuthorizationService
    from kingsec.domain import Role

    app: Application = request.app.state.kingsec_app
    authz: AuthorizationService = app.resolve(AuthorizationService)

    roles = []
    for role in Role:
        permissions = authz.get_permissions(role)
        roles.append(
            schemas.RolePermissionResponse(
                role=role.name,
                description=role.label,
                permissions=[p.value for p in permissions],
            )
        )
    return schemas.ListRolesResponse(roles=roles)
