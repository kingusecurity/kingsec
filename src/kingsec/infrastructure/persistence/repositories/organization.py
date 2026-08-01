from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from kingsec.application.ports.outbound.organization_repository import OrganizationRepository
from kingsec.domain.organization import (
    OrgActivityEvent,
    Organization,
    OrganizationId,
    OrganizationMembership,
    OrgRole,
    Team,
    TeamId,
    TeamMembership,
)
from kingsec.infrastructure.persistence.models import (
    OrgActivityEventORM,
    OrganizationMembershipORM,
    OrganizationORM,
    TeamMembershipORM,
    TeamORM,
)


class SQLAlchemyOrganizationRepository(OrganizationRepository):

    def __init__(self, session: Session) -> None:
        self._session = session

    # --- Organizations ---

    def save(self, org: Organization) -> None:
        existing = self._session.get(OrganizationORM, str(org.id))
        if existing is not None:
            existing.name = org.name
            existing.slug = org.slug
            existing.updated_at = datetime.now(UTC).isoformat()
        else:
            self._session.add(OrganizationORM(
                id=str(org.id),
                name=org.name,
                slug=org.slug,
                created_at=org.created_at,
                updated_at=org.updated_at,
            ))
        self._session.commit()

    def find_by_id(self, org_id: str) -> Organization | None:
        orm = self._session.get(OrganizationORM, org_id)
        if orm is None:
            return None
        return Organization(
            id=OrganizationId(orm.id),
            name=orm.name,
            slug=orm.slug,
            created_at=orm.created_at,
            updated_at=orm.updated_at,
        )

    def find_by_slug(self, slug: str) -> Organization | None:
        orm = self._session.execute(
            select(OrganizationORM).where(OrganizationORM.slug == slug)
        ).scalar_one_or_none()
        if orm is None:
            return None
        return Organization(
            id=OrganizationId(orm.id),
            name=orm.name,
            slug=orm.slug,
            created_at=orm.created_at,
            updated_at=orm.updated_at,
        )

    def list_all(self, limit: int = 50, offset: int = 0) -> list[Organization]:
        orms = self._session.execute(
            select(OrganizationORM).order_by(OrganizationORM.name).offset(offset).limit(limit)
        ).scalars().all()
        return [
            Organization(id=OrganizationId(o.id), name=o.name, slug=o.slug, created_at=o.created_at, updated_at=o.updated_at)
            for o in orms
        ]

    def delete(self, org_id: str) -> None:
        orm = self._session.get(OrganizationORM, org_id)
        if orm is not None:
            self._session.delete(orm)
            self._session.commit()

    def count(self) -> int:
        from sqlalchemy import func
        return self._session.execute(select(func.count(OrganizationORM.id))).scalar() or 0

    # --- Members ---

    def add_member(self, membership: OrganizationMembership) -> None:
        existing = self._session.execute(
            select(OrganizationMembershipORM).where(
                OrganizationMembershipORM.user_id == membership.user_id,
                OrganizationMembershipORM.organization_id == membership.organization_id,
            )
        ).scalar_one_or_none()
        if existing is None:
            self._session.add(OrganizationMembershipORM(
                user_id=membership.user_id,
                organization_id=membership.organization_id,
                role=membership.role.value,
                created_at=membership.created_at,
            ))
        self._session.commit()

    def remove_member(self, org_id: str, user_id: str) -> None:
        orm = self._session.execute(
            select(OrganizationMembershipORM).where(
                OrganizationMembershipORM.user_id == user_id,
                OrganizationMembershipORM.organization_id == org_id,
            )
        ).scalar_one_or_none()
        if orm is not None:
            self._session.delete(orm)
            self._session.commit()

    def list_members(self, org_id: str) -> list[OrganizationMembership]:
        orms = self._session.execute(
            select(OrganizationMembershipORM).where(
                OrganizationMembershipORM.organization_id == org_id
            )
        ).scalars().all()
        return [
            OrganizationMembership(
                user_id=m.user_id,
                organization_id=m.organization_id,
                role=OrgRole(m.role),
                created_at=m.created_at,
            )
            for m in orms
        ]

    def get_member_role(self, org_id: str, user_id: str) -> OrgRole | None:
        orm = self._session.execute(
            select(OrganizationMembershipORM).where(
                OrganizationMembershipORM.user_id == user_id,
                OrganizationMembershipORM.organization_id == org_id,
            )
        ).scalar_one_or_none()
        if orm is None:
            return None
        return OrgRole(orm.role)

    def list_user_orgs(self, user_id: str) -> list[OrganizationMembership]:
        orms = self._session.execute(
            select(OrganizationMembershipORM).where(
                OrganizationMembershipORM.user_id == user_id
            )
        ).scalars().all()
        return [
            OrganizationMembership(
                user_id=m.user_id,
                organization_id=m.organization_id,
                role=OrgRole(m.role),
                created_at=m.created_at,
            )
            for m in orms
        ]

    # --- Teams ---

    def save_team(self, team: Team) -> None:
        existing = self._session.get(TeamORM, str(team.id))
        if existing is not None:
            existing.name = team.name
            existing.description = team.description
            existing.updated_at = datetime.now(UTC).isoformat()
        else:
            self._session.add(TeamORM(
                id=str(team.id),
                organization_id=team.organization_id,
                name=team.name,
                description=team.description,
                created_at=team.created_at,
                updated_at=team.updated_at,
            ))
        self._session.commit()

    def find_team_by_id(self, team_id: str) -> Team | None:
        orm = self._session.get(TeamORM, team_id)
        if orm is None:
            return None
        return Team(
            id=TeamId(orm.id),
            organization_id=orm.organization_id,
            name=orm.name,
            description=orm.description,
            created_at=orm.created_at,
            updated_at=orm.updated_at,
        )

    def list_teams(self, org_id: str) -> list[Team]:
        orms = self._session.execute(
            select(TeamORM).where(TeamORM.organization_id == org_id).order_by(TeamORM.name)
        ).scalars().all()
        return [
            Team(id=TeamId(t.id), organization_id=t.organization_id, name=t.name, description=t.description,
                 created_at=t.created_at, updated_at=t.updated_at)
            for t in orms
        ]

    def delete_team(self, team_id: str) -> None:
        orm = self._session.get(TeamORM, team_id)
        if orm is not None:
            self._session.delete(orm)
            self._session.commit()

    def add_team_member(self, membership: TeamMembership) -> None:
        existing = self._session.execute(
            select(TeamMembershipORM).where(
                TeamMembershipORM.user_id == membership.user_id,
                TeamMembershipORM.team_id == membership.team_id,
            )
        ).scalar_one_or_none()
        if existing is None:
            self._session.add(TeamMembershipORM(
                user_id=membership.user_id,
                team_id=membership.team_id,
                created_at=membership.created_at,
            ))
        self._session.commit()

    def remove_team_member(self, team_id: str, user_id: str) -> None:
        orm = self._session.execute(
            select(TeamMembershipORM).where(
                TeamMembershipORM.user_id == user_id,
                TeamMembershipORM.team_id == team_id,
            )
        ).scalar_one_or_none()
        if orm is not None:
            self._session.delete(orm)
            self._session.commit()

    def list_team_members(self, team_id: str) -> list[TeamMembership]:
        orms = self._session.execute(
            select(TeamMembershipORM).where(TeamMembershipORM.team_id == team_id)
        ).scalars().all()
        return [
            TeamMembership(user_id=m.user_id, team_id=m.team_id, created_at=m.created_at)
            for m in orms
        ]

    # --- Activity ---

    def record_activity(self, event: OrgActivityEvent) -> None:
        self._session.add(OrgActivityEventORM(
            id=event.id,
            organization_id=event.organization_id,
            event_type=event.event_type.value,
            actor_id=event.actor_id,
            message=event.message,
            metadata_json=json.dumps({k: str(v) for k, v in event.metadata.items()}),
            timestamp=event.timestamp,
        ))
        self._session.commit()

    def list_activity(self, org_id: str, limit: int = 50) -> list[OrgActivityEvent]:
        orms = self._session.execute(
            select(OrgActivityEventORM)
            .where(OrgActivityEventORM.organization_id == org_id)
            .order_by(OrgActivityEventORM.timestamp.desc())
            .limit(limit)
        ).scalars().all()
        from kingsec.domain.organization import OrgEventType
        events_list = []
        for e in orms:
            try:
                et = OrgEventType(e.event_type)
            except ValueError:
                et = OrgEventType.ASSESSMENT_CREATED
            events_list.append(OrgActivityEvent(
                id=e.id,
                organization_id=e.organization_id,
                event_type=et,
                actor_id=e.actor_id,
                message=e.message,
                metadata=json.loads(e.metadata_json) if e.metadata_json else {},
                timestamp=e.timestamp,
            ))
        return events_list
