from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class PluginType(StrEnum):
    SCANNER = "scanner"
    AI = "ai"
    REPORT = "report"
    INTEGRATION = "integration"
    EXPORT = "export"
    NOTIFICATION = "notification"
    DASHBOARD_WIDGET = "dashboard_widget"
    COMPLIANCE = "compliance"
    THREAT_FEED = "threat_feed"
    AUTOMATION_ACTION = "automation_action"
    OTHER = "other"


class PluginPermission(StrEnum):
    FILESYSTEM_READ = "filesystem.read"
    FILESYSTEM_WRITE = "filesystem.write"
    NETWORK = "network"
    ASSESSMENT_READ = "assessment.read"
    ASSESSMENT_WRITE = "assessment.write"
    REPORTS = "reports"
    ASSETS = "assets"
    FINDINGS = "findings"
    NOTIFICATIONS = "notifications"
    THREAT_INTELLIGENCE = "threat_intelligence"
    AI = "ai"
    EXPOSURES = "exposures"
    ALERTS = "alerts"
    PLAYBOOKS = "playbooks"
    ADMIN = "admin"


@dataclass(frozen=True)
class PluginSdkManifest:
    id: str
    name: str
    version: str
    author: str = ""
    website: str = ""
    license: str = ""
    description: str = ""
    category: PluginType = PluginType.OTHER
    entrypoint: str = ""
    minimum_kingsec_version: str = "0.0.0"
    permissions: tuple[PluginPermission, ...] = ()
    dependencies: tuple[str, ...] = ()
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "website": self.website,
            "license": self.license,
            "description": self.description,
            "category": self.category.value,
            "entrypoint": self.entrypoint,
            "minimum_kingsec_version": self.minimum_kingsec_version,
            "permissions": [p.value for p in self.permissions],
            "dependencies": list(self.dependencies),
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PluginSdkManifest:
        return cls(
            id=data["id"],
            name=data.get("name", data["id"]),
            version=data.get("version", "0.0.0"),
            author=data.get("author", ""),
            website=data.get("website", ""),
            license=data.get("license", ""),
            description=data.get("description", ""),
            category=PluginType(data.get("category", "other")),
            entrypoint=data.get("entrypoint", ""),
            minimum_kingsec_version=data.get("minimum_kingsec_version", "0.0.0"),
            permissions=tuple(PluginPermission(p) for p in data.get("permissions", [])),
            dependencies=tuple(data.get("dependencies", [])),
            signature=data.get("signature", ""),
        )


@dataclass(frozen=True)
class PluginCatalogEntry:
    plugin_id: str
    name: str
    version: str
    author: str
    description: str
    category: PluginType
    license: str
    website: str
    downloads: int = 0
    rating: float = 0.0
    verified: bool = False
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class PluginCapability:
    plugin_type: PluginType
    hooks: tuple[str, ...] = ()
    permissions: tuple[PluginPermission, ...] = ()
    provides: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()


@dataclass(frozen=True)
class PluginRuntime:
    id: str
    name: str
    version: str
    type: PluginType
    permissions: tuple[PluginPermission, ...]
    loaded: bool = False
    entry_point: str = ""
    error: str = ""

    @classmethod
    def from_manifest(cls, manifest: PluginSdkManifest) -> PluginRuntime:
        return cls(
            id=manifest.id,
            name=manifest.name,
            version=manifest.version,
            type=manifest.category,
            permissions=manifest.permissions,
            entry_point=manifest.entrypoint,
        )
