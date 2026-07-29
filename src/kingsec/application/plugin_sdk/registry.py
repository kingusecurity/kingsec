from __future__ import annotations

import logging
from typing import Any

from kingsec.domain.plugin_extensions import (
    PluginCatalogEntry,
    PluginPermission,
    PluginRuntime,
    PluginSdkManifest,
    PluginType,
)

from .loader import PluginLoader
from .permissions import PermissionChecker, validate_manifest_permissions

logger = logging.getLogger(__name__)


class PluginRegistry:
    def __init__(self, loader: PluginLoader) -> None:
        self._loader = loader
        self._runtimes: dict[str, PluginRuntime] = {}
        self._manifests: dict[str, PluginSdkManifest] = {}
        self._checkers: dict[str, PermissionChecker] = {}

    def discover(self) -> list[PluginSdkManifest]:
        manifests = self._loader.discover()
        for m in manifests:
            self._manifests[m.id] = m
            self._runtimes[m.id] = PluginRuntime.from_manifest(m)
            self._checkers[m.id] = PermissionChecker(m)
        return manifests

    def load_plugin(self, plugin_id: str) -> PluginRuntime | None:
        manifest = self._manifests.get(plugin_id)
        if not manifest:
            logger.error("No manifest found for plugin %s", plugin_id)
            return None
        errors = validate_manifest_permissions(manifest)
        if errors:
            logger.error("Permission validation failed for %s: %s", plugin_id, errors)
            rt = self._runtimes.get(plugin_id)
            if rt:
                self._runtimes[plugin_id] = PluginRuntime(
                    id=rt.id, name=rt.name, version=rt.version,
                    type=rt.type, permissions=rt.permissions,
                    loaded=False, entry_point=rt.entry_point,
                    error="; ".join(errors),
                )
            return None
        instance = self._loader.load(manifest)
        if instance:
            self._runtimes[plugin_id] = PluginRuntime(
                id=manifest.id, name=manifest.name, version=manifest.version,
                type=manifest.category, permissions=manifest.permissions,
                loaded=True, entry_point=manifest.entrypoint,
            )
        else:
            rt = self._runtimes.get(plugin_id)
            if rt:
                self._runtimes[plugin_id] = PluginRuntime(
                    id=rt.id, name=rt.name, version=rt.version,
                    type=rt.type, permissions=rt.permissions,
                    loaded=False, entry_point=rt.entry_point,
                    error="Failed to instantiate plugin",
                )
        return self._runtimes.get(plugin_id)

    def unload_plugin(self, plugin_id: str) -> None:
        self._loader.unload(plugin_id)
        rt = self._runtimes.get(plugin_id)
        if rt:
            self._runtimes[plugin_id] = PluginRuntime(
                id=rt.id, name=rt.name, version=rt.version,
                type=rt.type, permissions=rt.permissions,
                loaded=False, entry_point=rt.entry_point,
            )

    def get_runtime(self, plugin_id: str) -> PluginRuntime | None:
        return self._runtimes.get(plugin_id)

    def list_runtimes(self) -> list[PluginRuntime]:
        return list(self._runtimes.values())

    def list_by_type(self, ptype: PluginType) -> list[PluginRuntime]:
        return [r for r in self._runtimes.values() if r.type == ptype]

    def get_manifest(self, plugin_id: str) -> PluginSdkManifest | None:
        return self._manifests.get(plugin_id)

    def check_permission(self, plugin_id: str, permission: PluginPermission) -> bool:
        checker = self._checkers.get(plugin_id)
        if not checker:
            return False
        return checker.check(permission)

    def get_loaded_instance(self, plugin_id: str) -> Any:
        return self._loader.get_loaded(plugin_id)

    def shutdown_all(self) -> None:
        self._loader.unload_all()
        self._runtimes.clear()
        self._manifests.clear()
        self._checkers.clear()


class PluginMarketplace:
    def __init__(self) -> None:
        self._catalog: dict[str, PluginCatalogEntry] = {}

    def seed_default_catalog(self) -> None:
        entries = [
            PluginCatalogEntry(
                plugin_id="kingsec-scanner-nmap", name="Nmap Scanner",
                version="1.0.0", author="KingSec", description="Network scanning via Nmap",
                category=PluginType.SCANNER, license="MIT", website="",
                downloads=1200, rating=4.5, verified=True,
                tags=("scanner", "nmap", "network"),
            ),
            PluginCatalogEntry(
                plugin_id="kingsec-ai-assistant", name="AI Assistant Plus",
                version="1.2.0", author="KingSec Labs", description="Enhanced AI analysis with custom models",
                category=PluginType.AI, license="MIT", website="",
                downloads=850, rating=4.2, verified=True,
                tags=("ai", "analysis", "llm"),
            ),
            PluginCatalogEntry(
                plugin_id="kingsec-report-pdf", name="PDF Report Generator",
                version="2.0.0", author="KingSec", description="Professional PDF security reports",
                category=PluginType.REPORT, license="MIT", website="",
                downloads=2100, rating=4.8, verified=True,
                tags=("report", "pdf", "document"),
            ),
            PluginCatalogEntry(
                plugin_id="kingsec-slack-notify", name="Slack Notifier",
                version="1.0.0", author="KingSec", description="Send alerts to Slack channels",
                category=PluginType.NOTIFICATION, license="MIT", website="",
                downloads=3400, rating=4.6, verified=True,
                tags=("slack", "notification", "messaging"),
            ),
            PluginCatalogEntry(
                plugin_id="kingsec-jira-integration", name="Jira Integration",
                version="1.1.0", author="KingSec", description="Create Jira tickets from findings",
                category=PluginType.INTEGRATION, license="MIT", website="",
                downloads=1800, rating=4.3, verified=True,
                tags=("jira", "ticketing", "integration"),
            ),
            PluginCatalogEntry(
                plugin_id="kingsec-siem-export", name="SIEM Event Export",
                version="1.0.0", author="KingSec", description="Export findings as SIEM events",
                category=PluginType.EXPORT, license="MIT", website="",
                downloads=950, rating=4.1, verified=True,
                tags=("siem", "export", "splunk"),
            ),
            PluginCatalogEntry(
                plugin_id="kingsec-compliance-nist", name="NIST 800-53 Mapper",
                version="1.0.0", author="KingSec", description="Map controls to NIST 800-53 framework",
                category=PluginType.COMPLIANCE, license="MIT", website="",
                downloads=650, rating=4.4, verified=True,
                tags=("compliance", "nist", "framework"),
            ),
            PluginCatalogEntry(
                plugin_id="kingsec-threat-mitre", name="MITRE ATT&CK Feed",
                version="1.0.0", author="KingSec", description="Live MITRE ATT&CK threat intelligence",
                category=PluginType.THREAT_FEED, license="MIT", website="",
                downloads=720, rating=4.0, verified=True,
                tags=("threat", "mitre", "intel"),
            ),
            PluginCatalogEntry(
                plugin_id="kingsec-widget-dashboard", name="Advanced Dashboard",
                version="1.0.0", author="KingSec", description="Custom dashboard widgets and charts",
                category=PluginType.DASHBOARD_WIDGET, license="MIT", website="",
                downloads=1500, rating=4.7, verified=True,
                tags=("dashboard", "widget", "chart"),
            ),
            PluginCatalogEntry(
                plugin_id="kingsec-auto-remediate", name="Auto Remediation",
                version="1.0.0", author="KingSec", description="Automated remediation playbook actions",
                category=PluginType.AUTOMATION_ACTION, license="MIT", website="",
                downloads=430, rating=3.9, verified=True,
                tags=("automation", "remediation", "playbook"),
            ),
        ]
        for entry in entries:
            self._catalog[entry.plugin_id] = entry

    def list_available(self) -> list[PluginCatalogEntry]:
        return list(self._catalog.values())

    def get_entry(self, plugin_id: str) -> PluginCatalogEntry | None:
        return self._catalog.get(plugin_id)

    def search(self, query: str) -> list[PluginCatalogEntry]:
        q = query.lower()
        return [
            entry for entry in self._catalog.values()
            if q in entry.name.lower()
            or q in entry.description.lower()
            or any(q in t.lower() for t in entry.tags)
        ]

    def filter_by_type(self, ptype: PluginType) -> list[PluginCatalogEntry]:
        return [e for e in self._catalog.values() if e.category == ptype]

    def add_entry(self, entry: PluginCatalogEntry) -> None:
        self._catalog[entry.plugin_id] = entry
