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

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from kingsec.application.ports.inbound.service_api import ServiceAPI
from kingsec.bootstrap.application import Application
from kingsec.domain import Role

from . import schemas
from .auth import CurrentUser, get_current_user, require_analyst, require_viewer
from .dependencies import get_service

router = APIRouter(prefix="/api/v1")


# ── Health ───────────────────────────────────────────────────────────────────


@router.get(
    "/health",
    response_model=schemas.HealthResponse,
    tags=["health"],
    summary="Health check",
    description="Returns service health status. Exposes no internal details.",
)
async def health_check() -> schemas.HealthResponse:
    return schemas.HealthResponse(status="ok")


# ── Auth ─────────────────────────────────────────────────────────────────────


def _get_login_use_case(request: Request):
    app: Application = request.app.state.kingsec_app  # type: ignore[attr-defined]
    from kingsec.application import Login
    return app.resolve(Login)


def _get_refresh_token_use_case(request: Request):
    app: Application = request.app.state.kingsec_app  # type: ignore[attr-defined]
    from kingsec.application import RefreshToken
    return app.resolve(RefreshToken)


def _get_register_user_use_case(request: Request):
    app: Application = request.app.state.kingsec_app  # type: ignore[attr-defined]
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
    login_uc=Depends(_get_login_use_case),
) -> schemas.LoginResponse:
    from kingsec.application.dto import LoginRequest

    request = LoginRequest(username=body.username, password=body.password)
    result = login_uc.execute(request)
    return schemas.LoginResponse(
        user_id=result.user_id,
        username=result.username,
        role=result.role,
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        token_type=result.token_type,
        expires_in=result.expires_in,
    )


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
    refresh_uc=Depends(_get_refresh_token_use_case),
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
    register_uc=Depends(_get_register_user_use_case),
) -> schemas.RegisterUserResponse:
    from kingsec.application.dto import RegisterUserRequest

    request = RegisterUserRequest(
        username=body.username,
        email=body.email,
        password=body.password,
        role=body.role,
    )
    result = register_uc.execute(request)
    return schemas.RegisterUserResponse(
        user_id=result.user_id,
        username=result.username,
        email=result.email,
        role=result.role,
    )


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
    from datetime import datetime, timezone

    app: Application = request.app.state.kingsec_app  # type: ignore[attr-defined]
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
    service: ServiceAPI = Depends(get_service),
) -> schemas.ListAssessmentsResponse:
    from kingsec.application.dto import ListAssessmentsRequest

    request = ListAssessmentsRequest(limit=limit, offset=offset)
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
    service: ServiceAPI = Depends(get_service),
) -> schemas.CreateAssessmentResponse:
    from kingsec.application.dto import CreateAssessmentRequest

    request = CreateAssessmentRequest(
        target_value=body.target_value,
        target_type=body.target_type,
        authorized_by=body.authorized_by,
        scope=body.scope,
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
    service: ServiceAPI = Depends(get_service),
) -> schemas.StartAssessmentResponse:
    from kingsec.application.dto import SubmitAssessmentRequest

    request = SubmitAssessmentRequest(assessment_id=assessment_id)
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
    service: ServiceAPI = Depends(get_service),
) -> schemas.AssessmentResponse:
    from kingsec.application.dto import GetAssessmentRequest

    request = GetAssessmentRequest(assessment_id=assessment_id)
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
            )
            for f in result.findings
        ],
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
    service: ServiceAPI = Depends(get_service),
) -> schemas.GenerateReportResponse:
    from kingsec.application.dto import GenerateReportRequest

    request = GenerateReportRequest(assessment_id=assessment_id)
    result = service.generate_report(request)
    return schemas.GenerateReportResponse(
        assessment_id=result.assessment_id,
        verdict=result.verdict,
        action_required=result.action_required,
        highest_severity=result.highest_severity,
        total_findings=result.total_findings,
        severity_counts=[
            schemas.SeverityCountResponse(severity=s.severity, count=s.count)
            for s in result.severity_counts
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
    service: ServiceAPI = Depends(get_service),
) -> schemas.CancelAssessmentResponse:
    from kingsec.application.dto import CancelAssessmentRequest

    request = CancelAssessmentRequest(assessment_id=assessment_id)
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
    service: ServiceAPI = Depends(get_service),
) -> None:
    from kingsec.application.dto import DeleteAssessmentRequest

    request = DeleteAssessmentRequest(assessment_id=assessment_id)
    service.delete_assessment(request)
