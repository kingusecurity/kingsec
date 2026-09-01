from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Request

from kingsec.application._support import check_assessment_access
from kingsec.application.ai import (
    AIChatService,
    ExecutiveSummaryService,
    ExplainFindingService,
    RemediationAssistantService,
)
from kingsec.domain import Role
from kingsec.domain.assessment import Assessment
from kingsec.domain.identifiers import AssessmentId
from kingsec.shared.errors import ExternalServiceError

from .auth import CurrentUser, get_current_user
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1/ai", tags=["ai-assistant"])


def _resolve(request: Request, service_type: type) -> Any:
    app: Application = get_application(request)
    svc = app.resolve(service_type)
    if svc is None:
        raise HTTPException(status_code=500, detail=f"{service_type.__name__} not available")
    return svc


def _get_repo(request: Request) -> Any:
    from kingsec.application.ports import AssessmentRepository
    return _resolve(request, AssessmentRepository)


def _is_admin(user: CurrentUser) -> bool:
    return user.role == Role.ADMIN


@router.post("/explain-finding")
async def explain_finding(
    body: dict[str, Any],
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    svc: ExplainFindingService = _resolve(request, ExplainFindingService)
    repo = _get_repo(request)
    finding_id = body.get("finding_id", "")
    assessment_id = body.get("assessment_id", "")
    if not finding_id or not assessment_id:
        raise HTTPException(status_code=400, detail="finding_id and assessment_id are required")
    assessment = repo.get(AssessmentId(assessment_id))
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    check_assessment_access(assessment, user.user_id, _is_admin(user))
    finding = next((f for f in assessment.findings if str(f.id) == finding_id), None)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    try:
        result = svc.explain(finding)
    except ExternalServiceError as e:
        raise HTTPException(status_code=502, detail=str(e)) from None
    return result


@router.post("/executive-summary")
async def executive_summary(
    body: dict[str, Any],
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    svc: ExecutiveSummaryService = _resolve(request, ExecutiveSummaryService)
    repo = _get_repo(request)
    assessment_id = body.get("assessment_id", "")
    if not assessment_id:
        raise HTTPException(status_code=400, detail="assessment_id is required")
    assessment = repo.get(AssessmentId(assessment_id))
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    check_assessment_access(assessment, user.user_id, _is_admin(user))
    try:
        result = svc.generate(assessment)
    except ExternalServiceError as e:
        raise HTTPException(status_code=502, detail=str(e)) from None
    return result


@router.post("/remediation-plan")
async def remediation_plan(
    body: dict[str, Any],
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    svc: RemediationAssistantService = _resolve(request, RemediationAssistantService)
    repo = _get_repo(request)
    assessment_id = body.get("assessment_id", "")
    if not assessment_id:
        raise HTTPException(status_code=400, detail="assessment_id is required")
    assessment = repo.get(AssessmentId(assessment_id))
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    check_assessment_access(assessment, user.user_id, _is_admin(user))
    try:
        result = svc.plan(list(assessment.findings))
    except ExternalServiceError as e:
        raise HTTPException(status_code=502, detail=str(e)) from None
    return result


@router.post("/chat")
async def ai_chat(
    body: dict[str, Any],
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    svc: AIChatService = _resolve(request, AIChatService)
    repo = _get_repo(request)
    question = body.get("question", "")
    if not question:
        raise HTTPException(status_code=400, detail="question is required")
    history = body.get("history", [])
    assessment_id = body.get("assessment_id")
    assessment: Assessment | None = None
    if assessment_id:
        assessment = repo.get(AssessmentId(assessment_id))
        if assessment is not None:
            check_assessment_access(assessment, user.user_id, _is_admin(user))
    try:
        result = svc.chat(question, history, assessment)
    except ExternalServiceError as e:
        raise HTTPException(status_code=502, detail=str(e)) from None
    return result


@router.get("/health")
async def ai_health(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    from kingsec.application.ai.ports import AIQueryPort
    ai: AIQueryPort = _resolve(request, AIQueryPort)
    return ai.health()
