"""Web adapter for authorization grants (Phase 4).

Role gating, decided per the user's own lean and rationale: create/revoke
are Admin-only. An Analyst who could self-grant their own authorization
would be able to authorize their own scans - the exact control this
feature exists to enforce would be bypassable by the population it is
meant to constrain. list is ANALYST and above (read access to what's
authorized is not the same privilege as deciding what's authorized).

    POST   /api/v1/authorization-grants        - create (ADMIN)
    GET    /api/v1/authorization-grants        - list   (ANALYST+)
    DELETE /api/v1/authorization-grants/{id}   - revoke (ADMIN)

The frontend's Authorization Grants page consumes these same routes; role
checks remain authoritative here at the HTTP boundary.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from kingsec.application.assessment_profiles import ExecutionPlanner
from kingsec.application.authorization_scope import effective_scan_surface, find_covering
from kingsec.application.dto import CreateAuthorizationGrantRequest, RevokeAuthorizationGrantRequest
from kingsec.application.ports import AuthorizationGrantRepository
from kingsec.application.ports.scanner_registry import ScannerPluginRegistry
from kingsec.domain import InvariantViolation, Target, TargetType

from . import schemas
from .auth import CurrentUser, require_admin, require_analyst

if TYPE_CHECKING:
    from kingsec.application.use_cases.create_authorization_grant import CreateAuthorizationGrant
    from kingsec.application.use_cases.revoke_authorization_grant import RevokeAuthorizationGrant
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1")


def _get_create_authorization_grant_use_case(request: Request) -> CreateAuthorizationGrant:
    app: Application = request.app.state.kingsec_app
    from kingsec.application.use_cases.create_authorization_grant import CreateAuthorizationGrant

    return cast("CreateAuthorizationGrant", app.resolve(CreateAuthorizationGrant))


def _get_revoke_authorization_grant_use_case(request: Request) -> RevokeAuthorizationGrant:
    app: Application = request.app.state.kingsec_app
    from kingsec.application.use_cases.revoke_authorization_grant import RevokeAuthorizationGrant

    return cast("RevokeAuthorizationGrant", app.resolve(RevokeAuthorizationGrant))


def _get_authorization_grant_repository(request: Request) -> AuthorizationGrantRepository:
    app: Application = request.app.state.kingsec_app
    return cast(AuthorizationGrantRepository, app.resolve(AuthorizationGrantRepository))


@router.post(
    "/authorization-grants",
    response_model=schemas.CreateAuthorizationGrantResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["authorization-grants"],
    summary="Create an authorization grant",
    description=(
        "Create an AuthorizationGrant licensing scans against a target. Requires ADMIN role: "
        "an Analyst who could self-grant their own authorization would be able to authorize "
        "their own scans, weakening the control this feature exists to enforce."
    ),
    dependencies=[Depends(require_admin)],
    responses={
        201: {"description": "Grant created"},
        400: {"description": "Validation error (bad target specification or timestamp)"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions (ADMIN required)"},
    },
)
async def create_authorization_grant(
    body: schemas.CreateAuthorizationGrantBody,
    user: CurrentUser = Depends(require_admin),
    use_case: CreateAuthorizationGrant = Depends(_get_create_authorization_grant_use_case),
) -> schemas.CreateAuthorizationGrantResponse:
    request = CreateAuthorizationGrantRequest(
        authorized_by=body.authorized_by,
        authorizing_organization=body.authorizing_organization,
        target_specification_type=body.target_specification_type,
        target_specification_value=body.target_specification_value,
        valid_from=body.valid_from,
        valid_until=body.valid_until,
        created_by=user.username,
    )
    result = use_case.execute(request)
    return schemas.CreateAuthorizationGrantResponse(
        grant_id=result.grant_id,
        target_specification_type=result.target_specification_type,
        target_specification_value=result.target_specification_value,
        valid_from=result.valid_from,
        valid_until=result.valid_until,
    )


@router.get(
    "/authorization-grants",
    tags=["authorization-grants"],
    summary="List authorization grants",
    description="List authorization grants, most recently created first. Requires ANALYST role or above.",
    dependencies=[Depends(require_analyst)],
    responses={
        200: {"description": "Grants matching the query"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions (ANALYST or above required)"},
    },
)
async def list_authorization_grants(
    limit: Annotated[int, Query(ge=1, le=200, description="Max results")] = 50,
    offset: Annotated[int, Query(ge=0, description="Results to skip")] = 0,
    repo: AuthorizationGrantRepository = Depends(_get_authorization_grant_repository),
) -> dict[str, Any]:
    grants = repo.list(limit=limit, offset=offset)
    return {
        "items": [
            {
                "id": str(g.id),
                "authorized_by": g.authorized_by,
                "authorizing_organization": g.authorizing_organization,
                "target_specification_type": g.target_specification.type.value,
                "target_specification_value": g.target_specification.value,
                "valid_from": g.valid_from.isoformat(),
                "valid_until": g.valid_until.isoformat(),
                "created_by": g.created_by,
                "revoked_at": g.revoked_at.isoformat() if g.revoked_at else None,
            }
            for g in grants
        ],
        "limit": limit,
        "offset": offset,
    }


@router.delete(
    "/authorization-grants/{grant_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["authorization-grants"],
    summary="Revoke an authorization grant",
    description="Revoke an authorization grant, stamped at the current UTC time. Requires ADMIN role.",
    dependencies=[Depends(require_admin)],
    responses={
        204: {"description": "Grant revoked"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions (ADMIN required)"},
        404: {"description": "Grant not found"},
    },
)
async def revoke_authorization_grant(
    grant_id: str,
    user: CurrentUser = Depends(require_admin),
    use_case: RevokeAuthorizationGrant = Depends(_get_revoke_authorization_grant_use_case),
) -> None:
    use_case.execute(RevokeAuthorizationGrantRequest(grant_id=grant_id, revoked_by=user.username))


@router.get(
    "/authorization-grants/check",
    response_model=schemas.CheckGrantCoverageResponse,
    tags=["authorization-grants"],
    summary="Check whether active grants cover a target+profile combination",
    description=(
        "Read-only dry run of the exact scope check CreateAssessment performs at "
        "submission time - calls effective_scan_surface()/find_covering() "
        "directly, never a reimplementation, so this can never drift from real "
        "enforcement. Lets the new-assessment UI warn an operator before they "
        "submit, instead of after. Requires ANALYST role or above."
    ),
    dependencies=[Depends(require_analyst)],
    responses={
        200: {"description": "Coverage result"},
        400: {"description": "Invalid target_type or target_value"},
        401: {"description": "Missing or invalid token"},
        403: {"description": "Insufficient permissions (ANALYST or above required)"},
        404: {"description": "Unknown profile_id"},
    },
)
async def check_grant_coverage(
    request: Request,
    target_type: Annotated[
        str,
        Query(
            description=(
                "One of: ip_address, hostname, url, network, domain, source_path, "
                "container_image"
            )
        ),
    ],
    target_value: Annotated[str, Query(min_length=1, max_length=2048)],
    profile_id: Annotated[str, Query(...)],
    _user: CurrentUser = Depends(require_analyst),
) -> schemas.CheckGrantCoverageResponse:
    app: Application = request.app.state.kingsec_app

    try:
        target = Target(value=target_value, type=TargetType(target_type))
    except (ValueError, InvariantViolation) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    planner = cast(ExecutionPlanner, app.resolve(ExecutionPlanner))
    profile = planner.get_profile(profile_id)
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown profile: {profile_id!r}")
    if target.type not in profile.supported_target_types:
        supported = ", ".join(item.value for item in profile.supported_target_types)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"profile {profile_id!r} does not support target type {target.type.value!r}; "
                f"expected one of: {supported}"
            ),
        )

    if not app.settings.security.enforce_authorization_scope:
        # Mirrors CreateAssessment's own rollback lever (Phase 4):
        # enforcement off means nothing would be checked or refused, so
        # there is nothing to warn about. Input validity is still checked
        # above: disabling grant enforcement must not make an impossible
        # profile/target combination look valid.
        return schemas.CheckGrantCoverageResponse(
            enforced=False,
            target_type=target_type,
            target_value=target_value,
            profile_id=profile_id,
            required_tiers=[],
            fully_covered=True,
        )

    registry = cast(ScannerPluginRegistry, app.resolve(ScannerPluginRegistry))
    required_tiers = effective_scan_surface(profile, registry, target.type)

    grants_repo: AuthorizationGrantRepository = cast(
        AuthorizationGrantRepository, app.resolve(AuthorizationGrantRepository)
    )
    now = datetime.now(UTC)
    active_grants = grants_repo.find_active(now)

    results: list[schemas.GrantCoverageTierResult] = []
    for tier in sorted(required_tiers, key=lambda t: t.value):
        grant = find_covering(active_grants, target, tier, now)
        results.append(
            schemas.GrantCoverageTierResult(
                tier=tier.value,
                covered=grant is not None,
                grant_id=str(grant.id) if grant else None,
            )
        )

    return schemas.CheckGrantCoverageResponse(
        enforced=True,
        target_type=target_type,
        target_value=target_value,
        profile_id=profile_id,
        required_tiers=results,
        fully_covered=all(r.covered for r in results),
    )
