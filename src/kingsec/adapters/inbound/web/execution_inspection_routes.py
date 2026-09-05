"""FastAPI routes for durable assessment-execution inspection (KSEC-103-01).

Admin-only, read-only visibility into the Phase 102 execution ledger.
VISIBILITY FIRST, RECOVERY LATER: nothing in this module writes to the
ledger, mutates an Assessment, or invokes a scanner - every route here
calls only ``ListAssessmentExecutions``/``GetAssessmentExecution``, which
are themselves backed exclusively by read-only repository queries.

Distinct from ``execution_routes.py``: that module exposes a VIEWER's own,
in-memory, per-assessment live progress (``AssessmentExecutionEngine`` -
ephemeral, owner-or-admin scoped). This module exposes an ADMIN's durable,
cross-assessment view of the Phase 102 ledger - a different audience, a
different (durable, not ephemeral) data source, and a different security
boundary (global admin only, no owner-scoped access at all).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from kingsec.application.assessment_execution_ledger import AssessmentExecutionStatus
from kingsec.application.use_cases.execution_inspection_dto import (
    ExecutionInspectionView,
    GetAssessmentExecutionRequest,
    ListAssessmentExecutionsRequest,
)

from .auth import CurrentUser, require_admin

if TYPE_CHECKING:
    from kingsec.application.use_cases.inspect_assessment_executions import (
        GetAssessmentExecution,
        ListAssessmentExecutions,
    )
    from kingsec.bootstrap.application import Application

router = APIRouter(
    prefix="/api/v1/assessment-executions",
    tags=["assessment-executions"],
    dependencies=[Depends(require_admin)],
)


def _get_list_use_case(request: Request) -> ListAssessmentExecutions:
    from kingsec.application.use_cases.inspect_assessment_executions import ListAssessmentExecutions

    app: Application = request.app.state.kingsec_app
    return cast("ListAssessmentExecutions", app.resolve(ListAssessmentExecutions))


def _get_single_use_case(request: Request) -> GetAssessmentExecution:
    from kingsec.application.use_cases.inspect_assessment_executions import GetAssessmentExecution

    app: Application = request.app.state.kingsec_app
    return cast("GetAssessmentExecution", app.resolve(GetAssessmentExecution))


def _view_to_dict(view: ExecutionInspectionView) -> dict[str, Any]:
    return {
        "execution_id": view.execution_id,
        "assessment_id": view.assessment_id,
        "execution_status": view.execution_status.value,
        "execution_version": view.execution_version,
        "execution_created_at": view.execution_created_at,
        "execution_updated_at": view.execution_updated_at,
        "assessment_status": view.assessment_status,
        "classification": view.classification.value,
        "schedule_occurrence_id": view.schedule_occurrence_id,
        "occurrence_key": view.occurrence_key,
        "schedule_id": view.schedule_id,
        "schedule_owner_user_id": view.schedule_owner_user_id,
    }


@router.get(
    "",
    summary="List durable assessment executions",
    description=(
        "Read-only, admin-only inspection of the Phase 102 durable execution ledger. "
        "Supports filtering to unresolved (REQUESTED/CLAIMED/RUNNING) executions and/or "
        "an exact execution status. Never mutates ledger state, never retries or resets "
        "an execution, and never invokes a scanner."
    ),
    responses={
        200: {"description": "Paginated execution inspection records"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions (ADMIN required)"},
    },
)
async def list_assessment_executions(
    request: Request,
    current_user: CurrentUser = Depends(require_admin),
    unresolved_only: bool = Query(False, description="Restrict to REQUESTED/CLAIMED/RUNNING executions"),
    status_filter: AssessmentExecutionStatus | None = Query(
        None, alias="status", description="Restrict to an exact execution status"
    ),
    limit: int = Query(50, ge=1, le=200, description="Max results"),
    offset: int = Query(0, ge=0, description="Results to skip"),
) -> dict[str, Any]:
    use_case = _get_list_use_case(request)
    result = use_case.execute(
        ListAssessmentExecutionsRequest(
            unresolved_only=unresolved_only,
            status=status_filter,
            limit=limit,
            offset=offset,
            requesting_user=current_user.user_id,
            requesting_username=current_user.username,
        )
    )
    return {
        "items": [_view_to_dict(v) for v in result.items],
        "total": result.total,
        "limit": result.limit,
        "offset": result.offset,
    }


@router.get(
    "/{execution_id}",
    summary="Get one durable assessment execution",
    description="Read-only, admin-only lookup of a single execution's full inspection context.",
    responses={
        200: {"description": "Execution inspection record"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions (ADMIN required)"},
        404: {"description": "No execution exists with that id"},
    },
)
async def get_assessment_execution(
    execution_id: str,
    request: Request,
    current_user: CurrentUser = Depends(require_admin),
) -> dict[str, Any]:
    use_case = _get_single_use_case(request)
    view = use_case.execute(
        GetAssessmentExecutionRequest(
            execution_id=execution_id,
            requesting_user=current_user.user_id,
            requesting_username=current_user.username,
        )
    )
    if view is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No execution found with that id",
        )
    return _view_to_dict(view)
