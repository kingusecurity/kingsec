"""Authorization service — check roles, permissions, and resource ownership.

This is an application-layer service (not a port) because its logic *is* the
policy — there is no infrastructure implementation to swap.  The composition
root registers it as a singleton on the DI container so the web adapter can
resolve it for route-level guards.

Ownership checks (``check_ownership``) are provided as a convenience for
endpoints where a non-admin user may act only on resources they created
(e.g. cancelling one's own scan job).
"""

from __future__ import annotations

from kingsec.domain import Role

from .permissions import ROLE_PERMISSIONS, Permission


class AuthorizationService:
    """Stateless role & permission checker."""

    def has_permission(self, role: Role, permission: Permission) -> bool:
        """Return ``True`` when *role* is granted *permission*."""
        return permission in ROLE_PERMISSIONS.get(role, frozenset())

    def has_any_role(self, role: Role, *roles: Role) -> bool:
        """Return ``True`` when *role* is one of the given *roles*."""
        return role in roles

    def get_permissions(self, role: Role) -> frozenset[Permission]:
        """Return the full set of permissions for *role*."""
        return ROLE_PERMISSIONS.get(role, frozenset())

    def check_ownership(
        self,
        *,
        resource_owner_id: str,
        current_user_id: str,
        current_role: Role,
    ) -> bool:
        """Return ``True`` when the current user can act on the resource.

        Admins may act on any resource.  Non-admins may act only on
        resources they own.
        """
        if current_role == Role.ADMIN:
            return True
        return current_user_id == resource_owner_id
