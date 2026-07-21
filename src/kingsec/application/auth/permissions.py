"""Permission model and role-to-permission policy.

Notable decisions
    - ``Permission`` is a plain ``Enum``, not an ``IntEnum``, because
      permissions have no natural ordering.
    - ``ROLE_PERMISSIONS`` maps each ``Role`` to the **exact** set of
      ``Permission`` values that role is allowed.  Admin gets *all*
      permissions via ``frozenset(Permission)``.
    - The policy is deliberately static (compile-time) — no runtime
      permission-registration mechanism.  If new operations are added,
      the corresponding permissions must be added here.
"""

from __future__ import annotations

from enum import Enum

from kingsec.domain import Role


class Permission(Enum):
    """Granular action a user may (or may not) perform."""

    CREATE_SCAN = "create_scan"
    LIST_SCANS = "list_scans"
    VIEW_REPORTS = "view_reports"
    DOWNLOAD_REPORTS = "download_reports"
    READ_REPORTS = "read_reports"
    READ_SUMMARIES = "read_summaries"
    READ_HEALTH = "read_health"

    # API Key management permissions (Phase 8.3)
    CREATE_API_KEY = "create_api_key"
    LIST_API_KEYS = "list_api_keys"
    ROTATE_API_KEY = "rotate_api_key"
    DELETE_API_KEY = "delete_api_key"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset(
        {
            Permission.READ_REPORTS,
            Permission.READ_SUMMARIES,
            Permission.READ_HEALTH,
        }
    ),
    Role.ANALYST: frozenset(
        {
            Permission.CREATE_SCAN,
            Permission.LIST_SCANS,
            Permission.VIEW_REPORTS,
            Permission.DOWNLOAD_REPORTS,
            Permission.CREATE_API_KEY,
            Permission.LIST_API_KEYS,
            Permission.ROTATE_API_KEY,
            Permission.DELETE_API_KEY,
        }
    ),
    Role.ADMIN: frozenset(Permission),
}
