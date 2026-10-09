"""Assessment profile REST routes.

Read-only profile listing and execution plan generation. No domain entities
or scanner architecture are modified.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any, cast

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Request, status

from kingsec.application.assessment_profiles import ExecutionPlanner
from kingsec.domain import InvariantViolation, Target
from kingsec.domain.target import TargetType

from .dependencies import get_application


def _get_execution_planner(request: Request) -> ExecutionPlanner:
    """Resolve the same configured planner used for assessment execution."""
    return cast(ExecutionPlanner, get_application(request).resolve(ExecutionPlanner))


def create_profiles_router(
    *,
    get_current_user: Callable[..., Any] | None = None,
) -> APIRouter:
    """Create an ``APIRouter`` with profile endpoints.

    All endpoints require authentication.
    """
    router = APIRouter(prefix="/profiles", tags=["profiles"])

    # ── GET /profiles ─────────────────────────────────────────────────

    @router.get("")
    async def list_profiles(
        _user: Any = Depends(get_current_user),
        planner: ExecutionPlanner = Depends(_get_execution_planner),
    ) -> list[dict[str, Any]]:
        """Return all available assessment profiles."""
        profiles = planner.list_profiles()
        return [planner.profile_to_dict(p) for p in profiles]

    # ── GET /profiles/{profile_id} ─────────────────────────────────────

    @router.get("/{profile_id}")
    async def get_profile(
        profile_id: Annotated[
            str,
            Path(
                description="Profile identifier (e.g. quick-scan, web-scan)",
                pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$",
            ),
        ],
        _user: Any = Depends(get_current_user),
        planner: ExecutionPlanner = Depends(_get_execution_planner),
    ) -> dict[str, Any]:
        """Return a single profile's details."""
        profile = planner.get_profile(profile_id)
        if profile is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Unknown profile: {profile_id!r}",
            )
        return planner.profile_to_dict(profile)

    # ── POST /profiles/{profile_id}/plan ───────────────────────────────

    @router.post("/{profile_id}/plan")
    async def generate_plan(
        profile_id: Annotated[
            str,
            Path(description="Profile identifier"),
        ],
        body: Annotated[dict[str, Any], Body()],
        _user: Any = Depends(get_current_user),
        planner: ExecutionPlanner = Depends(_get_execution_planner),
    ) -> dict[str, Any]:
        """Generate an execution plan for the given profile and target."""
        profile = planner.get_profile(profile_id)
        if profile is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Unknown profile: {profile_id!r}",
            )

        raw_target = body.get("target", "")
        if not raw_target or not isinstance(raw_target, str) or not raw_target.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="target must be a non-empty string",
            )

        raw_type = body.get("target_type", "")
        if not raw_type or not isinstance(raw_type, str):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="target_type is required",
            )

        try:
            target_type = TargetType(raw_type)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid target_type: {raw_type!r}. Valid: {', '.join(t.value for t in TargetType)}",
            ) from None

        try:
            target = Target(raw_target.strip(), target_type)
        except InvariantViolation as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc

        try:
            plan = planner.plan(profile_id, target.value, target.type)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(e),
            ) from e

        return planner.plan_to_dict(plan)

    return router
