from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.organization_repository import OrganizationRepository
from kingsec.domain.organization import (
    OrgActivityEvent,
    Organization,
    OrganizationId,
    OrganizationMembership,
    OrgEventType,
    OrgRole,
    Team,
    TeamId,
    TeamMembership,
)

from .auth import CurrentUser, get_current_user, require_admin, require_viewer
from .dependencies import get_application

if TYPE_CHECKING:
    from kingsec.bootstrap.application import Application

router = APIRouter(prefix="/api/v1", tags=["organizations"])


def _get_repo(request: Request) -> OrganizationRepository:
    from fastapi import HTTPException
    app: Application = get_application(request)
    repo: OrganizationRepository | None = app.resolve(OrganizationRepository)
    if repo is None:
        raise HTTPException(status_code=500, detail="Organization repository not available")
    return repo


def _get_audit(request: Request) -> Any:
    app: Application = get_application(request)
    return app.resolve(AuditPublisher)


def _slugify(name: str) -> str:
    return name.lower().replace(" ", "-").replace("_", "-")[:64]


def _record_activity(
    repo: OrganizationRepository,
    org_id: str,
    event_type: OrgEventType,
    actor_id: str,
    message: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    event = OrgActivityEvent(
        id=str(uuid.uuid4()),
        organization_id=org_id,
        event_type=event_type,
        actor_id=actor_id,
        message=message,
        metadata=metadata or {},
    )
    repo.record_activity(event)


# ── Organizations ─────────────────────────────────────────────────────────


@router.get("/organizations")
async def list_organizations(
    limit: int = 50,
    offset: int = 0,
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(require_viewer),
) -> dict[str, Any]:
    repo = _get_repo(request)
    orgs = repo.list_all(limit=limit, offset=offset)
    total = repo.count()
    return {
        "organizations": [
            {"id": str(o.id), "name": o.name, "slug": o.slug, "created_at": o.created_at, "updated_at": o.updated_at}
            for o in orgs
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("/organizations", status_code=status.HTTP_201_CREATED)
async def create_organization(
    body: dict[str, Any],
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    repo = _get_repo(request)
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Organization name is required")
    slug = body.get("slug", _slugify(name))
    existing = repo.find_by_slug(slug)
    if existing:
        raise HTTPException(status_code=409, detail=f"Organization with slug '{slug}' already exists")
    org = Organization(id=OrganizationId.generate(), name=name, slug=slug)
    repo.save(org)
    repo.add_member(OrganizationMembership(
        user_id=user.user_id,
        organization_id=str(org.id),
        role=OrgRole.ADMIN,
    ))
    _record_activity(repo, str(org.id), OrgEventType.USER_JOINED, user.user_id, f"Organization '{name}' created")
    return {"id": str(org.id), "name": org.name, "slug": org.slug, "created_at": org.created_at}


@router.patch("/organizations/{org_id}")
async def update_organization(
    org_id: str,
    body: dict[str, Any],
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    repo = _get_repo(request)
    org = repo.find_by_id(org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    role = repo.get_member_role(org_id, user.user_id)
    if role not in (OrgRole.ADMIN,):
        raise HTTPException(status_code=403, detail="Only admins can update organization")
    if "name" in body:
        org.name = body["name"].strip()
    if "slug" in body:
        slug = body["slug"].strip()
        existing = repo.find_by_slug(slug)
        if existing and str(existing.id) != org_id:
            raise HTTPException(status_code=409, detail=f"Slug '{slug}' already in use")
        org.slug = slug
    repo.save(org)
    return {"id": str(org.id), "name": org.name, "slug": org.slug, "updated_at": org.updated_at}


@router.delete("/organizations/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(
    org_id: str,
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(require_admin),
) -> None:
    repo = _get_repo(request)
    org = repo.find_by_id(org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    repo.delete(org_id)


# ── Members ─────────────────────────────────────────────────────────────────


@router.get("/organizations/{org_id}/members")
async def list_members(
    org_id: str,
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(require_viewer),
) -> dict[str, Any]:
    repo = _get_repo(request)
    org = repo.find_by_id(org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    # KSEC-71-03: require_viewer only checks the caller's global role, not
    # membership in this specific organization - every mutating route in
    # this file already calls get_member_role first; this read route must too.
    if repo.get_member_role(org_id, user.user_id) is None:
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    members = repo.list_members(org_id)
    return {
        "members": [
            {"user_id": m.user_id, "organization_id": m.organization_id, "role": m.role.value, "created_at": m.created_at}
            for m in members
        ],
        "total": len(members),
    }


@router.post("/organizations/{org_id}/members", status_code=status.HTTP_201_CREATED)
async def add_member(
    org_id: str,
    body: dict[str, Any],
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    repo = _get_repo(request)
    org = repo.find_by_id(org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    role = repo.get_member_role(org_id, user.user_id)
    if role not in (OrgRole.ADMIN,):
        raise HTTPException(status_code=403, detail="Only admins can add members")
    target_user_id = body.get("user_id", "")
    if not target_user_id:
        raise HTTPException(status_code=400, detail="user_id is required")
    existing_role = repo.get_member_role(org_id, target_user_id)
    if existing_role is not None:
        raise HTTPException(status_code=409, detail="User is already a member")
    member_role = OrgRole(body.get("role", "viewer"))
    membership = OrganizationMembership(
        user_id=target_user_id,
        organization_id=org_id,
        role=member_role,
    )
    repo.add_member(membership)
    _record_activity(repo, org_id, OrgEventType.USER_JOINED, user.user_id, f"User {target_user_id} joined")
    return {"user_id": target_user_id, "organization_id": org_id, "role": member_role.value}


@router.delete("/organizations/{org_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    org_id: str,
    user_id: str,
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(get_current_user),
) -> None:
    repo = _get_repo(request)
    org = repo.find_by_id(org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    role = repo.get_member_role(org_id, user.user_id)
    if role not in (OrgRole.ADMIN,) and user.user_id != user_id:
        raise HTTPException(status_code=403, detail="Only admins can remove members")
    repo.remove_member(org_id, user_id)


# ── My Organizations ────────────────────────────────────────────────────────


@router.get("/me/organizations")
async def my_organizations(
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    repo = _get_repo(request)
    memberships = repo.list_user_orgs(user.user_id)
    orgs = []
    for m in memberships:
        org = repo.find_by_id(m.organization_id)
        if org:
            orgs.append({
                "id": str(org.id),
                "name": org.name,
                "slug": org.slug,
                "role": m.role.value,
                "created_at": org.created_at,
            })
    return {"organizations": orgs}


# ── Teams ────────────────────────────────────────────────────────────────────


@router.get("/teams")
async def list_teams(
    organization_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(require_viewer),
) -> dict[str, Any]:
    repo = _get_repo(request)
    if organization_id:
        teams = repo.list_teams(organization_id)
    else:
        teams = []
    return {
        "teams": [
            {"id": str(t.id), "organization_id": t.organization_id, "name": t.name, "description": t.description,
             "created_at": t.created_at, "updated_at": t.updated_at}
            for t in teams
        ],
        "total": len(teams),
    }


@router.post("/teams", status_code=status.HTTP_201_CREATED)
async def create_team(
    body: dict[str, Any],
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    repo = _get_repo(request)
    org_id = body.get("organization_id", "")
    if not org_id:
        raise HTTPException(status_code=400, detail="organization_id is required")
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Team name is required")
    role = repo.get_member_role(org_id, user.user_id)
    if role not in (OrgRole.ADMIN,):
        raise HTTPException(status_code=403, detail="Only organization admins can create teams")
    team = Team(id=TeamId.generate(), organization_id=org_id, name=name, description=body.get("description", ""))
    repo.save_team(team)
    return {"id": str(team.id), "organization_id": team.organization_id, "name": team.name, "description": team.description}


@router.patch("/teams/{team_id}")
async def update_team(
    team_id: str,
    body: dict[str, Any],
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    repo = _get_repo(request)
    team = repo.find_team_by_id(team_id)
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found")
    role = repo.get_member_role(team.organization_id, user.user_id)
    if role not in (OrgRole.ADMIN,):
        raise HTTPException(status_code=403, detail="Only organization admins can update teams")
    if "name" in body:
        team.name = body["name"].strip()
    if "description" in body:
        team.description = body["description"]
    repo.save_team(team)
    return {"id": str(team.id), "name": team.name, "description": team.description}


@router.delete("/teams/{team_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_team(
    team_id: str,
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(get_current_user),
) -> None:
    repo = _get_repo(request)
    team = repo.find_team_by_id(team_id)
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found")
    role = repo.get_member_role(team.organization_id, user.user_id)
    if role not in (OrgRole.ADMIN,):
        raise HTTPException(status_code=403, detail="Only organization admins can delete teams")
    repo.delete_team(team_id)


# ── Team Members ─────────────────────────────────────────────────────────────


@router.post("/teams/{team_id}/members", status_code=status.HTTP_201_CREATED)
async def add_team_member(
    team_id: str,
    body: dict[str, Any],
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    repo = _get_repo(request)
    team = repo.find_team_by_id(team_id)
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found")
    role = repo.get_member_role(team.organization_id, user.user_id)
    if role not in (OrgRole.ADMIN,):
        raise HTTPException(status_code=403, detail="Only organization admins can manage team members")
    target_user_id = body.get("user_id", "")
    if not target_user_id:
        raise HTTPException(status_code=400, detail="user_id is required")
    repo.add_team_member(TeamMembership(user_id=target_user_id, team_id=team_id))
    return {"user_id": target_user_id, "team_id": team_id}


@router.delete("/teams/{team_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_team_member(
    team_id: str,
    user_id: str,
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(get_current_user),
) -> None:
    repo = _get_repo(request)
    team = repo.find_team_by_id(team_id)
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found")
    role = repo.get_member_role(team.organization_id, user.user_id)
    if role not in (OrgRole.ADMIN,):
        raise HTTPException(status_code=403, detail="Only organization admins can manage team members")
    repo.remove_team_member(team_id, user_id)


# ── Activity ─────────────────────────────────────────────────────────────────


@router.get("/organizations/{org_id}/activity")
async def list_activity(
    org_id: str,
    limit: int = 50,
    request: Request = None,  # type: ignore[assignment]
    user: CurrentUser = Depends(require_viewer),
) -> dict[str, Any]:
    repo = _get_repo(request)
    org = repo.find_by_id(org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    # KSEC-71-03: same membership check as list_members - require_viewer
    # alone does not establish that the caller belongs to this organization.
    if repo.get_member_role(org_id, user.user_id) is None:
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    events = repo.list_activity(org_id, limit=limit)
    return {
        "events": [
            {
                "id": e.id,
                "organization_id": e.organization_id,
                "event_type": e.event_type.value if hasattr(e.event_type, 'value') else e.event_type,
                "actor_id": e.actor_id,
                "message": e.message,
                "metadata": {k: str(v) for k, v in e.metadata.items()},
                "timestamp": e.timestamp,
            }
            for e in events
        ],
        "total": len(events),
    }
