from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.plugin_package import PluginInstallStatus, PluginPackage


class PluginRepositoryPort(ABC):
    """Read-write persistence for plugin packages."""

    @abstractmethod
    def save(self, plugin: PluginPackage) -> None:
        ...

    @abstractmethod
    def find_by_id(self, plugin_id: str) -> PluginPackage | None:
        ...

    @abstractmethod
    def find_all(self) -> list[PluginPackage]:
        ...

    @abstractmethod
    def delete(self, plugin_id: str) -> None:
        ...

    @abstractmethod
    def update_status(self, plugin_id: str, status: PluginInstallStatus) -> None:
        ...

    @abstractmethod
    def update_health(self, plugin_id: str, health: str, error_message: str) -> None:
        ...
