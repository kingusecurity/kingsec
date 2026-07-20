from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.plugin_package import PluginManifest


class PluginInstallerPort(ABC):
    """Handles filesystem operations for plugin installation."""

    @abstractmethod
    def install(self, package_path: str, manifest: PluginManifest) -> str:
        """Extract plugin to target dir. Returns install path."""
        ...

    @abstractmethod
    def uninstall(self, plugin_id: str) -> None:
        """Remove plugin files from filesystem."""
        ...

    @abstractmethod
    def rollback(self, plugin_id: str, backup_path: str) -> str | None:
        """Restore previous version from backup. Returns restored path."""
        ...
