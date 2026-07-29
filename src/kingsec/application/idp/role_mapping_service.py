"""Role and group mapping from external identity attributes to KingSec roles."""

from __future__ import annotations

from kingsec.domain.enums import Role
from kingsec.domain.identity import IdentityProvider, RoleMappingRule

ADMIN_GROUPS = frozenset({"admin", "administrator", "domain admins", "enterprise admins"})
MANAGER_GROUPS = frozenset({"manager", "team lead", "supervisor"})


class RoleMappingService:
    def resolve_role(self, provider: IdentityProvider, external_groups: list[str]) -> Role:
        if not provider.role_mappings and not external_groups:
            return Role.VIEWER
        matched: list[RoleMappingRule] = []
        for mapping in provider.role_mappings:
            if mapping.external_group.lower() in [g.lower() for g in external_groups]:
                matched.append(mapping)
        if matched:
            matched.sort(key=lambda m: m.priority, reverse=True)
            return Role[matched[0].kingsec_role.upper()]
        for group in external_groups:
            gl = group.lower()
            if gl in ADMIN_GROUPS:
                return Role.ADMIN
            if gl in MANAGER_GROUPS:
                return Role.ANALYST
        return Role.VIEWER

    def resolve_role_from_domain(self, provider: IdentityProvider, email: str) -> Role:
        return Role.VIEWER