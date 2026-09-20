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

Frontend is out of scope this round (see CHANGELOG.md) - this route plus
documented curl usage is the deliverable; a UI is logged as a follow-up.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, cast

from fastapi import APIRouter, Depends, Query, Request, status

from kingsec.application.dto import CreateAuthorizationGrantRequest, RevokeAuthorizationGrantRequest
from kingsec.application.ports import AuthorizationGrantRepository

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
