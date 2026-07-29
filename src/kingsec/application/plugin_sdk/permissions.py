from __future__ import annotations

from typing import Any

from kingsec.domain.plugin_extensions import PluginPermission, PluginSdkManifest, PluginType


class PermissionChecker:
    def __init__(self, manifest: PluginSdkManifest) -> None:
        self._manifest = manifest
        self._granted = set(manifest.permissions)

    def check(self, permission: PluginPermission) -> bool:
        return permission in self._granted

    def check_any(self, *permissions: PluginPermission) -> bool:
        return any(p in self._granted for p in permissions)

    def check_all(self, *permissions: PluginPermission) -> bool:
        return all(p in self._granted for p in permissions)

    @property
    def permissions(self) -> tuple[PluginPermission, ...]:
        return self._manifest.permissions

    def assert_permission(self, permission: PluginPermission) -> None:
        if not self.check(permission):
            raise PermissionError(
                f"Plugin '{self._manifest.name}' does not have required permission: {permission.value}"
            )


TYPE_REQUIRED_PERMISSIONS: dict[PluginType, tuple[PluginPermission, ...]] = {
    PluginType.SCANNER: (PluginPermission.FILESYSTEM_READ, PluginPermission.NETWORK),
    PluginType.AI: (PluginPermission.AI,),
    PluginType.REPORT: (PluginPermission.REPORTS, PluginPermission.FILESYSTEM_WRITE),
    PluginType.INTEGRATION: (PluginPermission.NETWORK,),
    PluginType.EXPORT: (PluginPermission.REPORTS, PluginPermission.FILESYSTEM_WRITE),
    PluginType.NOTIFICATION: (PluginPermission.NOTIFICATIONS, PluginPermission.NETWORK),
    PluginType.DASHBOARD_WIDGET: (),
    PluginType.COMPLIANCE: (PluginPermission.FINDINGS, PluginPermission.ASSESSMENT_READ),
    PluginType.THREAT_FEED: (PluginPermission.THREAT_INTELLIGENCE, PluginPermission.NETWORK),
    PluginType.AUTOMATION_ACTION: (PluginPermission.PLAYBOOKS,),
    PluginType.OTHER: (),
}


def validate_manifest_permissions(manifest: PluginSdkManifest) -> list[str]:
    errors: list[str] = []
    required = TYPE_REQUIRED_PERMISSIONS.get(manifest.category, ())
    for perm in required:
        if perm not in manifest.permissions:
            errors.append(
                f"Plugin type '{manifest.category.value}' requires permission '{perm.value}', "
                f"but it is not declared in manifest"
            )
    return errors


def build_sandbox_config(manifest: PluginSdkManifest) -> dict[str, Any]:
    return {
        "plugin_id": manifest.id,
        "plugin_name": manifest.name,
        "permissions": [p.value for p in manifest.permissions],
        "allow_filesystem_read": PluginPermission.FILESYSTEM_READ in manifest.permissions,
        "allow_filesystem_write": PluginPermission.FILESYSTEM_WRITE in manifest.permissions,
        "allow_network": PluginPermission.NETWORK in manifest.permissions,
        "allow_ai": PluginPermission.AI in manifest.permissions,
        "restrict_paths": manifest.category == PluginType.SCANNER,
    }
