"""Integration tests for the organization API - KSEC-71-03 (Phase 72).

Phase 71 discovered, and this phase remediates, a cross-tenant BOLA/IDOR:
GET /api/v1/organizations/{org_id}/members and .../activity required only
require_viewer (a global role check), with no repo.get_member_role(org_id,
user.user_id) check, unlike every mutating route in organization_routes.py.
Any authenticated user - including one belonging to zero organizations -
could read another organization's membership roster and activity log.

These tests exercise the real router and a real (in-memory)
OrganizationRepository implementation - no mocked authorization logic.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
from kingsec.adapters.inbound.web.dependencies import get_application
from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
from kingsec.application.ports.outbound.organization_repository import OrganizationRepository
from kingsec.domain import Role
from kingsec.domain.organization import (
    OrgActivityEvent,
    Organization,
    OrganizationId,
    OrganizationMembership,
    OrgEventType,
    OrgRole,
    Team,
    TeamMembership,
)


class InMemoryOrgRepo(OrganizationRepository):
    def __init__(self) -> None:
        self._orgs: dict[str, Organization] = {}
        self._members: list[OrganizationMembership] = []
        self._activity: list[OrgActivityEvent] = []
        self._teams: dict[str, Team] = {}
        self._team_members: list[TeamMembership] = []

    def save(self, org: Organization) -> None:
        self._orgs[str(org.id)] = org

    def find_by_id(self, org_id: str) -> Organization | None:
        return self._orgs.get(org_id)

    def find_by_slug(self, slug: str) -> Organization | None:
        return next((o for o in self._orgs.values() if o.slug == slug), None)

    def list_all(self, limit: int = 50, offset: int = 0) -> list[Organization]:
        return list(self._orgs.values())[offset : offset + limit]

    def delete(self, org_id: str) -> None:
        self._orgs.pop(org_id, None)

    def count(self) -> int:
        return len(self._orgs)

    def add_member(self, membership: OrganizationMembership) -> None:
        self._members.append(membership)

    def remove_member(self, org_id: str, user_id: str) -> None:
        self._members = [m for m in self._members if not (m.organization_id == org_id and m.user_id == user_id)]

    def list_members(self, org_id: str) -> list[OrganizationMembership]:
        return [m for m in self._members if m.organization_id == org_id]

    def get_member_role(self, org_id: str, user_id: str) -> OrgRole | None:
        m = next((m for m in self._members if m.organization_id == org_id and m.user_id == user_id), None)
        return m.role if m else None

    def list_user_orgs(self, user_id: str) -> list[OrganizationMembership]:
        return [m for m in self._members if m.user_id == user_id]

    def save_team(self, team: Team) -> None:
        self._teams[str(team.id)] = team

    def find_team_by_id(self, team_id: str) -> Team | None:
        return self._teams.get(team_id)

    def list_teams(self, org_id: str) -> list[Team]:
        return [t for t in self._teams.values() if t.organization_id == org_id]

    def delete_team(self, team_id: str) -> None:
        self._teams.pop(team_id, None)

    def add_team_member(self, membership: TeamMembership) -> None:
        self._team_members.append(membership)

    def remove_team_member(self, team_id: str, user_id: str) -> None:
        self._team_members = [m for m in self._team_members if not (m.team_id == team_id and m.user_id == user_id)]

    def list_team_members(self, team_id: str) -> list[TeamMembership]:
        return [m for m in self._team_members if m.team_id == team_id]

    def record_activity(self, event: OrgActivityEvent) -> None:
        self._activity.append(event)

    def list_activity(self, org_id: str, limit: int = 50) -> list[OrgActivityEvent]:
        return [e for e in self._activity if e.organization_id == org_id][:limit]


class ActorHolder:
    def __init__(self, user_id: str = "acme_owner", role: Role = Role.VIEWER) -> None:
        self.user_id = user_id
        self.role = role

    def as_current_user(self) -> CurrentUser:
        return CurrentUser(
            user_id=self.user_id,
            username=self.user_id,
            role=self.role,
            claims=None,  # type: ignore[arg-type]
        )


@pytest.fixture
def actor() -> ActorHolder:
    return ActorHolder(user_id="acme_owner", role=Role.VIEWER)


@pytest.fixture
def repo() -> InMemoryOrgRepo:
    return InMemoryOrgRepo()


@pytest.fixture
def app(actor: ActorHolder, repo: InMemoryOrgRepo) -> FastAPI:
    class FakeApplication:
        def resolve(self, port: type) -> object:
            if port is OrganizationRepository:
                return repo
            return None

    async def override_get_current_user() -> CurrentUser:
        return actor.as_current_user()

    from kingsec.adapters.inbound.web.organization_routes import router

    fastapi_app = FastAPI()
    fastapi_app.include_router(router)
    fastapi_app.state.kingsec_app = FakeApplication()
    fastapi_app.dependency_overrides[get_current_user] = override_get_current_user
    fastapi_app.dependency_overrides[get_application] = lambda request=None: fastapi_app.state.kingsec_app
    register_error_handlers(fastapi_app)
    return fastapi_app


ACME = "org-acme"
GLOBEX = "org-globex"


def _seed_two_orgs(repo: InMemoryOrgRepo) -> None:
    repo.save(Organization(id=OrganizationId(value=ACME), name="Acme Corp", slug="acme"))
    repo.add_member(OrganizationMembership(user_id="acme_owner", organization_id=ACME, role=OrgRole.ADMIN))
    repo.add_member(OrganizationMembership(user_id="acme_employee", organization_id=ACME, role=OrgRole.EDITOR))
    repo.record_activity(
        OrgActivityEvent(
            id="evt-acme-1",
            organization_id=ACME,
            event_type=OrgEventType.USER_JOINED,
            actor_id="acme_owner",
            message="acme_employee was invited to Acme Corp",
        )
    )

    repo.save(Organization(id=OrganizationId(value=GLOBEX), name="Globex Corp", slug="globex"))
    repo.add_member(OrganizationMembership(user_id="globex_owner", organization_id=GLOBEX, role=OrgRole.ADMIN))
    repo.record_activity(
        OrgActivityEvent(
            id="evt-globex-1",
            organization_id=GLOBEX,
            event_type=OrgEventType.USER_JOINED,
            actor_id="globex_owner",
            message="Globex Corp was created",
        )
    )


class TestOrganizationMembersAuthorization:
    def test_member_can_list_members(self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo) -> None:
        _seed_two_orgs(repo)
        actor.user_id = "acme_owner"
        client = TestClient(app)
        resp = client.get(f"/api/v1/organizations/{ACME}/members")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

    def test_non_admin_member_can_also_list_members(self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo) -> None:
        """Reading is a lower bar than mutating - any existing role
        (not just OrgRole.ADMIN) may list, matching the required-behavior
        spec's 'organization member: allowed', distinct from the
        ADMIN-only mutation checks elsewhere in this file."""
        _seed_two_orgs(repo)
        actor.user_id = "acme_employee"
        client = TestClient(app)
        resp = client.get(f"/api/v1/organizations/{ACME}/members")
        assert resp.status_code == 200

    def test_non_member_cannot_list_members(self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo) -> None:
        _seed_two_orgs(repo)
        actor.user_id = "mallory"
        client = TestClient(app)
        resp = client.get(f"/api/v1/organizations/{ACME}/members")
        assert resp.status_code == 403

    def test_user_belonging_to_zero_organizations_cannot_list_members(
        self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo
    ) -> None:
        _seed_two_orgs(repo)
        assert repo.get_member_role(ACME, "mallory") is None
        actor.user_id = "mallory"
        client = TestClient(app)
        resp = client.get(f"/api/v1/organizations/{ACME}/members")
        assert resp.status_code == 403

    def test_user_from_organization_b_cannot_list_organization_a_members(
        self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo
    ) -> None:
        _seed_two_orgs(repo)
        actor.user_id = "globex_owner"
        client = TestClient(app)
        resp = client.get(f"/api/v1/organizations/{ACME}/members")
        assert resp.status_code == 403

    def test_denied_response_contains_no_membership_records(
        self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo
    ) -> None:
        _seed_two_orgs(repo)
        actor.user_id = "mallory"
        client = TestClient(app)
        resp = client.get(f"/api/v1/organizations/{ACME}/members")
        assert resp.status_code == 403
        assert "acme_owner" not in resp.text
        assert "acme_employee" not in resp.text

    def test_nonexistent_organization_returns_404_not_403(
        self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo
    ) -> None:
        """Preserve the existing behavior: existence is checked before
        membership, exactly like update_organization/add_member/etc."""
        actor.user_id = "mallory"
        client = TestClient(app)
        resp = client.get("/api/v1/organizations/does-not-exist/members")
        assert resp.status_code == 404


class TestOrganizationActivityAuthorization:
    def test_member_can_list_activity(self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo) -> None:
        _seed_two_orgs(repo)
        actor.user_id = "acme_owner"
        client = TestClient(app)
        resp = client.get(f"/api/v1/organizations/{ACME}/activity")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_non_member_cannot_list_activity(self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo) -> None:
        _seed_two_orgs(repo)
        actor.user_id = "mallory"
        client = TestClient(app)
        resp = client.get(f"/api/v1/organizations/{ACME}/activity")
        assert resp.status_code == 403

    def test_user_belonging_to_zero_organizations_cannot_list_activity(
        self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo
    ) -> None:
        _seed_two_orgs(repo)
        actor.user_id = "mallory"
        client = TestClient(app)
        resp = client.get(f"/api/v1/organizations/{ACME}/activity")
        assert resp.status_code == 403

    def test_user_from_organization_b_cannot_list_organization_a_activity(
        self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo
    ) -> None:
        _seed_two_orgs(repo)
        actor.user_id = "globex_owner"
        client = TestClient(app)
        resp = client.get(f"/api/v1/organizations/{ACME}/activity")
        assert resp.status_code == 403

    def test_denied_response_contains_no_activity_records(
        self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo
    ) -> None:
        _seed_two_orgs(repo)
        actor.user_id = "mallory"
        client = TestClient(app)
        resp = client.get(f"/api/v1/organizations/{ACME}/activity")
        assert resp.status_code == 403
        assert "acme_employee was invited" not in resp.text

    def test_nonexistent_organization_returns_404_not_403(
        self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo
    ) -> None:
        actor.user_id = "mallory"
        client = TestClient(app)
        resp = client.get("/api/v1/organizations/does-not-exist/activity")
        assert resp.status_code == 404


class TestOrganizationExistingChecksUnweakened:
    """Phase 72 Section 5: must not weaken update_organization/add_member/
    remove_member/create_team/update_team/delete_team/add_team_member/
    remove_team_member - each still requires org-role ADMIN specifically,
    not merely any membership."""

    def test_non_admin_member_cannot_update_organization(
        self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo
    ) -> None:
        _seed_two_orgs(repo)
        actor.user_id = "acme_employee"  # EDITOR, not ADMIN
        client = TestClient(app)
        resp = client.patch(f"/api/v1/organizations/{ACME}", json={"name": "Hijacked"})
        assert resp.status_code == 403

    def test_org_admin_can_update_organization(self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo) -> None:
        _seed_two_orgs(repo)
        actor.user_id = "acme_owner"
        client = TestClient(app)
        resp = client.patch(f"/api/v1/organizations/{ACME}", json={"name": "Acme Corp Renamed"})
        assert resp.status_code == 200

    def test_non_admin_member_cannot_add_member(self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo) -> None:
        _seed_two_orgs(repo)
        actor.user_id = "acme_employee"
        client = TestClient(app)
        resp = client.post(f"/api/v1/organizations/{ACME}/members", json={"user_id": "new_person"})
        assert resp.status_code == 403


class TestOrganizationCrossTenantIdorRegression:
    """Phase 72 / permanent regression test converting the Phase 71 proof
    (prove_org_cross_tenant_idor.py) into a committed test."""

    def test_mallory_cannot_read_acme_members_or_activity(
        self, app: FastAPI, actor: ActorHolder, repo: InMemoryOrgRepo
    ) -> None:
        _seed_two_orgs(repo)
        assert repo.get_member_role(ACME, "mallory") is None

        actor.user_id = "mallory"
        actor.role = Role.VIEWER
        client = TestClient(app)

        members_resp = client.get(f"/api/v1/organizations/{ACME}/members")
        assert members_resp.status_code == 403
        assert "acme_owner" not in members_resp.text
        assert "acme_employee" not in members_resp.text

        activity_resp = client.get(f"/api/v1/organizations/{ACME}/activity")
        assert activity_resp.status_code == 403
        assert "acme_employee was invited" not in activity_resp.text

        # A real Acme member still sees exactly what mallory could not.
        actor.user_id = "acme_owner"
        acme_members = client.get(f"/api/v1/organizations/{ACME}/members")
        assert acme_members.status_code == 200
        assert acme_members.json()["total"] == 2
