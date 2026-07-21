"""Tests for Permission enum, ROLE_PERMISSIONS policy, and AuthorizationService."""

from __future__ import annotations

from kingsec.application.auth import ROLE_PERMISSIONS, AuthorizationService, Permission
from kingsec.domain import Role


class TestPermissionEnum:
    def test_all_permissions_have_unique_values(self) -> None:
        values = [p.value for p in Permission]
        assert len(values) == len(set(values))

    def test_admin_has_all_permissions(self) -> None:
        admin_perms = ROLE_PERMISSIONS[Role.ADMIN]
        assert admin_perms == frozenset(Permission)

    def test_analyst_permissions(self) -> None:
        analyst_perms = ROLE_PERMISSIONS[Role.ANALYST]
        assert Permission.CREATE_SCAN in analyst_perms
        assert Permission.LIST_SCANS in analyst_perms
        assert Permission.VIEW_REPORTS in analyst_perms
        assert Permission.DOWNLOAD_REPORTS in analyst_perms
        assert Permission.READ_REPORTS not in analyst_perms
        assert Permission.READ_SUMMARIES not in analyst_perms
        assert Permission.READ_HEALTH not in analyst_perms

    def test_viewer_permissions(self) -> None:
        viewer_perms = ROLE_PERMISSIONS[Role.VIEWER]
        assert Permission.READ_REPORTS in viewer_perms
        assert Permission.READ_SUMMARIES in viewer_perms
        assert Permission.READ_HEALTH in viewer_perms
        assert Permission.CREATE_SCAN not in viewer_perms
        assert Permission.LIST_SCANS not in viewer_perms
        assert Permission.VIEW_REPORTS not in viewer_perms
        assert Permission.DOWNLOAD_REPORTS not in viewer_perms


class TestAuthorizationService:
    def setup_method(self) -> None:
        self.authz = AuthorizationService()

    # ── has_permission ─────────────────────────────────────────────────

    def test_admin_has_permission(self) -> None:
        for perm in Permission:
            assert self.authz.has_permission(Role.ADMIN, perm)

    def test_analyst_has_create_scan(self) -> None:
        assert self.authz.has_permission(Role.ANALYST, Permission.CREATE_SCAN)

    def test_analyst_does_not_have_read_reports(self) -> None:
        assert not self.authz.has_permission(Role.ANALYST, Permission.READ_REPORTS)

    def test_viewer_does_not_have_create_scan(self) -> None:
        assert not self.authz.has_permission(Role.VIEWER, Permission.CREATE_SCAN)

    def test_viewer_has_read_health(self) -> None:
        assert self.authz.has_permission(Role.VIEWER, Permission.READ_HEALTH)

    def test_unknown_role_has_no_permissions(self) -> None:
        from kingsec.application.auth.permissions import ROLE_PERMISSIONS, Permission

        assert Permission.CREATE_SCAN not in ROLE_PERMISSIONS.get(None, frozenset())  # type: ignore[arg-type]

    # ── has_any_role ───────────────────────────────────────────────────

    def test_has_any_role_single_match(self) -> None:
        assert self.authz.has_any_role(Role.ANALYST, Role.ANALYST)

    def test_has_any_role_multiple_match(self) -> None:
        assert self.authz.has_any_role(Role.ADMIN, Role.ANALYST, Role.ADMIN)

    def test_has_any_role_no_match(self) -> None:
        assert not self.authz.has_any_role(Role.VIEWER, Role.ANALYST, Role.ADMIN)

    # ── get_permissions ────────────────────────────────────────────────

    def test_get_permissions_admin(self) -> None:
        perms = self.authz.get_permissions(Role.ADMIN)
        assert perms == frozenset(Permission)

    def test_get_permissions_viewer(self) -> None:
        perms = self.authz.get_permissions(Role.VIEWER)
        assert Permission.READ_HEALTH in perms
        assert Permission.CREATE_SCAN not in perms

    # ── check_ownership ────────────────────────────────────────────────

    def test_admin_owns_any_resource(self) -> None:
        assert self.authz.check_ownership(
            resource_owner_id="user-123",
            current_user_id="admin-999",
            current_role=Role.ADMIN,
        )

    def test_analyst_owns_own_resource(self) -> None:
        assert self.authz.check_ownership(
            resource_owner_id="user-123",
            current_user_id="user-123",
            current_role=Role.ANALYST,
        )

    def test_analyst_does_not_own_other_resource(self) -> None:
        assert not self.authz.check_ownership(
            resource_owner_id="user-123",
            current_user_id="user-456",
            current_role=Role.ANALYST,
        )

    def test_viewer_does_not_own_other_resource(self) -> None:
        assert not self.authz.check_ownership(
            resource_owner_id="user-abc",
            current_user_id="user-xyz",
            current_role=Role.VIEWER,
        )
