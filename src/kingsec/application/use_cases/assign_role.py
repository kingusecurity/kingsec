"""Use case: assign a role to a user (admin-only).

Only an authenticated administrator can change a user's role.
The last administrator in the system cannot be demoted.
"""

from __future__ import annotations

import logging

from kingsec.application.dto import AssignRoleRequest, AssignRoleResponse
from kingsec.application.errors import ApplicationError
from kingsec.application.ports import AuditPublisher, UserRepository
from kingsec.domain import Role
from kingsec.domain.audit import AuditAction, AuditEntry


class AssignRole:
    """Assign a new role to a user (admin-only)."""

    def __init__(
        self,
        users: UserRepository,
        audit: AuditPublisher | None = None,
    ) -> None:
        self._users = users
        self._audit = audit

    def execute(self, request: AssignRoleRequest) -> AssignRoleResponse:
        try:
            new_role = Role[request.new_role.upper()]
        except KeyError as exc:
            raise AssignRoleError(f"invalid role: {request.new_role}") from exc

        admin = self._users.find_by_id(request.requesting_user_id)
        if admin is None:
            raise AssignRoleError("requesting user not found")
        if admin.role != Role.ADMIN:
            raise AssignRoleError("insufficient permissions")

        target = self._users.find_by_id(request.target_user_id)
        if target is None:
            raise AssignRoleError("target user not found")

        if target.role == Role.ADMIN and new_role != Role.ADMIN:
            admin_count = self._users.count_by_role(Role.ADMIN)
            if admin_count <= 1:
                raise AssignRoleError("cannot demote the last administrator")

        if new_role == target.role:
            raise AssignRoleError(f"user already has role '{new_role.label}'")

        target.change_role(new_role)
        self._users.save(target)

        self._publish_audit(
            AuditEntry(
                action=AuditAction.ROLE_CHANGED,
                resource_type="user",
                resource_id=target.id,
                success=True,
                user_id=request.requesting_user_id,
                username=admin.username,
                role=admin.role.label,
                metadata={"target_user": target.username, "new_role": new_role.label},
            )
        )

        return AssignRoleResponse(
            user_id=target.id,
            username=target.username,
            email=target.email,
            new_role=target.role.label,
        )

    def _publish_audit(self, entry: AuditEntry) -> None:
        if self._audit is None:
            return
        try:
            self._audit.record(entry)
        except Exception as exc:
            logging.getLogger(__name__).warning("audit publish failed (best-effort): %s", exc)


class AssignRoleError(ApplicationError):
    """Raised when role assignment fails."""
