from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.organization import (
    OrgActivityEvent,
    Organization,
    OrganizationMembership,
    OrgRole,
    Team,
    TeamMembership,
)


class OrganizationRepository(ABC):

    @abstractmethod
    def save(self, org: Organization) -> None: ...

    @abstractmethod
    def find_by_id(self, org_id: str) -> Organization | None: ...

    @abstractmethod
    def find_by_slug(self, slug: str) -> Organization | None: ...

    @abstractmethod
    def list_all(self, limit: int = 50, offset: int = 0) -> list[Organization]: ...

    @abstractmethod
    def delete(self, org_id: str) -> None: ...

    @abstractmethod
    def count(self) -> int: ...

    # --- Members ---

    @abstractmethod
    def add_member(self, membership: OrganizationMembership) -> None: ...

    @abstractmethod
    def remove_member(self, org_id: str, user_id: str) -> None: ...

    @abstractmethod
    def list_members(self, org_id: str) -> list[OrganizationMembership]: ...

    @abstractmethod
    def get_member_role(self, org_id: str, user_id: str) -> OrgRole | None: ...

    @abstractmethod
    def list_user_orgs(self, user_id: str) -> list[OrganizationMembership]: ...

    # --- Teams ---

    @abstractmethod
    def save_team(self, team: Team) -> None: ...

    @abstractmethod
    def find_team_by_id(self, team_id: str) -> Team | None: ...

    @abstractmethod
    def list_teams(self, org_id: str) -> list[Team]: ...

    @abstractmethod
    def delete_team(self, team_id: str) -> None: ...

    @abstractmethod
    def add_team_member(self, membership: TeamMembership) -> None: ...

    @abstractmethod
    def remove_team_member(self, team_id: str, user_id: str) -> None: ...

    @abstractmethod
    def list_team_members(self, team_id: str) -> list[TeamMembership]: ...

    # --- Activity ---

    @abstractmethod
    def record_activity(self, event: OrgActivityEvent) -> None: ...

    @abstractmethod
    def list_activity(self, org_id: str, limit: int = 50) -> list[OrgActivityEvent]: ...
