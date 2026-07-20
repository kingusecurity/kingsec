from __future__ import annotations

from kingsec.infrastructure.plugin.marketplace import MarketplaceClient


class TestMarketplaceClient:
    def setup_method(self) -> None:
        self.client = MarketplaceClient()

    def test_check_updates_returns_empty(self) -> None:
        updates = self.client.check_updates("test-plugin", "1.0.0")
        assert updates == []

    def test_fetch_plugin_returns_empty_bytes(self) -> None:
        data = self.client.fetch_plugin("test-plugin", "1.0.0")
        assert data == b""
