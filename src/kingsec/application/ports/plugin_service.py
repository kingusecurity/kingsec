from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.plugin_package import PluginHealth, PluginInstallStatus, PluginPackage


class PluginServicePort(ABC):
    """Inbound port for plugin lifecycle management."""

    @abstractmethod
    def install(self, package_path: str, filename: str) -> PluginPackage:
        ...

    @abstractmethod
    def uninstall(self, plugin_id: str) -> None:
        ...

    @abstractmethod
    def enable(self, plugin_id: str) -> PluginPackage:
        ...

    @abstractmethod
    def disable(self, plugin_id: str) -> PluginPackage:
        ...

    @abstractmethod
    def update(self, plugin_id: str, package_path: str, filename: str) -> PluginPackage:
        ...

    @abstractmethod
    def rollback(self, plugin_id: str) -> PluginPackage | None:
        ...

    @abstractmethod
    def validate(self, package_path: str) -> dict:
        ...

    @abstractmethod
    def list_plugins(self) -> list[PluginPackage]:
        ...

    @abstractmethod
    def get_plugin(self, plugin_id: str) -> PluginPackage | None:
        ...

    @abstractmethod
    def check_updates(self, plugin_id: str) -> list[dict]:
        ...

    @abstractmethod
    def import_plugin(self, package_path: str, filename: str) -> PluginPackage:
        ...

    @abstractmethod
    def export_plugin(self, plugin_id: str) -> bytes | None:
        ...
