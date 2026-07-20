from __future__ import annotations

from kingsec.application.ports.outbound import PluginMarketplacePort


class MarketplaceClient(PluginMarketplacePort):
    """Remote plugin registry client.

    In production this would connect to a real registry API.
    Current implementation is a stub returning empty results for testing.
    """

    def __init__(self, registry_url: str = "https://github.com/kingusecurity/kingsec-plugins") -> None:
        self._registry_url = registry_url

    def check_updates(self, plugin_id: str, current_version: str) -> list[dict]:
        _ = plugin_id
        _ = current_version
        return []

    def fetch_plugin(self, plugin_id: str, version: str) -> bytes:
        _ = plugin_id
        _ = version
        return b""
