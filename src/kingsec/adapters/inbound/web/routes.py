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
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status

from kingsec.application.ports.inbound.service_api import ServiceAPI

from . import schemas
from .dependencies import get_service

router = APIRouter(prefix="/api/v1")


# ── Health ───────────────────────────────────────────────────────────────────


@router.get(
    "/health",
    response_model=schemas.HealthResponse,
    tags=["health"],
)
async def health_check() -> schemas.HealthResponse:
    return schemas.HealthResponse(status="ok")


# ── List Assessments ─────────────────────────────────────────────────────────


@router.get(
    "/assessments",
    response_model=schemas.ListAssessmentsResponse,
    tags=["assessments"],
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
