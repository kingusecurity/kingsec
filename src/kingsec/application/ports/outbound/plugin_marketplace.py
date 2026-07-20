from __future__ import annotations

from abc import ABC, abstractmethod


class PluginMarketplacePort(ABC):
    """Remote plugin registry integration."""

    @abstractmethod
    def check_updates(self, plugin_id: str, current_version: str) -> list[dict]:
        """Check for available updates. Returns list of version info dicts."""
        ...

    @abstractmethod
    def fetch_plugin(self, plugin_id: str, version: str) -> bytes:
        """Download plugin package bytes from remote registry."""
        ...
