"""FastAPI routes for assessment execution progress monitoring.

Provides live per-scanner progress, execution phase tracking, and
cancellation for running assessments.  The ``AssessmentExecutionEngine``
is resolved from the DI container at request time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from kingsec.domain import Role

from .auth import CurrentUser, require_analyst, require_viewer

if TYPE_CHECKING:
    from kingsec.application.assessment_execution import AssessmentExecutionEngine
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1/assessments", tags=["execution"])


def _is_admin(user: CurrentUser) -> bool:
    return user.role == Role.ADMIN


def _get_engine(request: Request) -> Any:
    app: Application = request.app.state.kingsec_app
    from kingsec.application.assessment_execution import AssessmentExecutionEngine

    return app.resolve(AssessmentExecutionEngine)


def _check_owns_assessment(request: Request, assessment_id: str, current_user: CurrentUser) -> None:
    """Raise AssessmentNotFoundError (-> 404) unless the caller owns this
    assessment or is Admin — matches the check used by the assessment
    CRUD routes in routes.py, so execution status/events cannot be used to
    probe another user's assessments.
    """
    from kingsec.application._support import check_assessment_access
    from kingsec.application.ports import AssessmentRepository
    from kingsec.domain import AssessmentId

    app: Application = request.app.state.kingsec_app
    assessments: AssessmentRepository = app.resolve(AssessmentRepository)
    check_assessment_access(
        assessments.get(AssessmentId(assessment_id)), current_user.user_id, _is_admin(current_user)
    )


def _scanner_progress_to_dict(sp: Any) -> dict[str, Any]:
    # Phase 06 added a blanket _sanitize_scanner_error() here because
    # sp.error was recorded unsanitized (orchestrator.py's engine.fail_scanner
    # call) and, by this layer, had already lost the original exception's
    # type - the only fail-closed option left was to collapse every value to
    # a generic string. Phase 07 sanitizes at that true source instead
    # (ScannerOrchestrator.execute()'s wrapping), using
    # safe_failure_message()'s existing three-branch split before the type
    # information is lost - so sp.error is safe by construction by the time
    # it reaches here, and re-collapsing it a second time would only destroy
    # the specificity that fix restores (e.g. "The security scan could not
    # be completed." collapsing further into "An unexpected error
    # occurred..."). Removed, not kept as defence-in-depth: a second,
    # blanket pass over an already-safe value has no security benefit here,
    # only a usability cost - see the Phase 07 report §3.3 for the fuller
    # reasoning, including why "keep it as defence-in-depth" was rejected.
    return {
        "scanner_id": sp.scanner_id,
        "name": sp.name,
        "status": sp.status,
        "start_time": sp.start_time,
        "end_time": sp.end_time,
        "duration_seconds": sp.duration_seconds,
        "findings_count": sp.findings_count,
        "warnings": list(sp.warnings),
        "error": sp.error,
        "skipped_reason": sp.skipped_reason,
    }


def _event_to_dict(ev: Any) -> dict[str, Any]:
    return {
        "event_type": ev.event_type,
        "scanner_id": ev.scanner_id,
        "timestamp": ev.timestamp,
        "message": ev.message,
        "progress_percent": ev.progress_percent,
    }


# ── GET /assessments/{id}/execution/status ───────────────────────────────


@router.get(
    "/{assessment_id}/execution/status",
    dependencies=[Depends(require_viewer)],
    summary="Get execution status",
    description="Returns current execution phase and per-scanner progress.",
    responses={
        200: {"description": "Execution status"},
        404: {"description": "Assessment not found or not being executed"},
    },
)
async def get_execution_status(
    assessment_id: str,
    request: Request,
    current_user: CurrentUser = Depends(require_viewer),
) -> dict[str, Any]:
    _check_owns_assessment(request, assessment_id, current_user)
    engine: AssessmentExecutionEngine = _get_engine(request)
    state = engine.get_state(assessment_id)
    if state is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Execution not found for this assessment",
        )
    return {
        "assessment_id": state.assessment_id,
        "phase": state.phase.value,
        "progress_percent": state.progress_percent,
        "scanner_progress": [_scanner_progress_to_dict(sp) for sp in state.scanner_progress],
        "started_at": state.started_at,
        "completed_at": state.completed_at,
        "error_message": state.error_message,
    }


# ── GET /assessments/{id}/execution/events ────────────────────────────────


@router.get(
    "/{assessment_id}/execution/events",
    dependencies=[Depends(require_viewer)],
    summary="Get execution events",
    description="Returns ordered lifecycle events for a running or completed execution.",
    responses={
        200: {"description": "Ordered list of events"},
        404: {"description": "Assessment not found"},
    },
)
async def get_execution_events(
    assessment_id: str,
    request: Request,
    current_user: CurrentUser = Depends(require_viewer),
) -> dict[str, Any]:
    _check_owns_assessment(request, assessment_id, current_user)
    engine: AssessmentExecutionEngine = _get_engine(request)
    if engine.get_state(assessment_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Execution not found for this assessment",
        )
    events = engine.get_events(assessment_id)
    return {
        "assessment_id": assessment_id,
        "events": [_event_to_dict(ev) for ev in events],
    }


# ── GET /assessments/{id}/execution/progress ──────────────────────────────


@router.get(
    "/{assessment_id}/execution/progress",
    dependencies=[Depends(require_viewer)],
    summary="Get execution progress",
    description="Returns the overall progress percentage for a running execution.",
    responses={
        200: {"description": "Progress percentage"},
        404: {"description": "Assessment not found"},
    },
)
async def get_execution_progress(
    assessment_id: str,
    request: Request,
    current_user: CurrentUser = Depends(require_viewer),
) -> dict[str, Any]:
    _check_owns_assessment(request, assessment_id, current_user)
    engine: AssessmentExecutionEngine = _get_engine(request)
    progress = engine.get_progress(assessment_id)
    if progress is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Execution not found for this assessment",
        )
    return {
        "assessment_id": assessment_id,
        "progress_percent": progress,
    }


# ── POST /assessments/{id}/execution/cancel ───────────────────────────────


@router.post(
    "/{assessment_id}/execution/cancel",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_analyst)],
    summary="Cancel execution",
    description="Cancel a running assessment execution.",
    responses={
        200: {"description": "Execution cancelled"},
        409: {"description": "Execution is already in a terminal state"},
        404: {"description": "Assessment not found"},
    },
)
async def cancel_execution(
    assessment_id: str,
    request: Request,
    current_user: CurrentUser = Depends(require_analyst),
) -> dict[str, Any]:
    _check_owns_assessment(request, assessment_id, current_user)
    engine: AssessmentExecutionEngine = _get_engine(request)
    cancelled = engine.cancel_execution(assessment_id)
    if not cancelled:
        state = engine.get_state(assessment_id)
        if state is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Execution not found for this assessment",
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot cancel execution in phase {state.phase.value}",
        )
    return {
        "assessment_id": assessment_id,
        "status": "cancelled",
    }
