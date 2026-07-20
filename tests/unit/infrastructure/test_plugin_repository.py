from __future__ import annotations

from kingsec.domain.plugin_package import (
    PluginHealth,
    PluginInstallStatus,
    PluginManifest,
    PluginPackage,
    PluginVersion,
)
from kingsec.infrastructure.plugin.repository import InMemoryPluginRepository


class TestInMemoryPluginRepository:
    def setup_method(self) -> None:
        self.repo = InMemoryPluginRepository()
        self.manifest = PluginManifest(id="p1", name="Test", version=PluginVersion(1, 0, 0))
        self.pkg = PluginPackage(id="p1", manifest=self.manifest, status=PluginInstallStatus.INSTALLED)

    def test_save_and_find(self) -> None:
        self.repo.save(self.pkg)
        found = self.repo.find_by_id("p1")
        assert found is not None
        assert found.id == "p1"
        assert found.status == PluginInstallStatus.INSTALLED

    def test_find_not_found(self) -> None:
        assert self.repo.find_by_id("nonexistent") is None

    def test_find_all(self) -> None:
        self.repo.save(self.pkg)
        m2 = PluginManifest(id="p2", name="Test2", version=PluginVersion(2, 0, 0))
        p2 = PluginPackage(id="p2", manifest=m2, status=PluginInstallStatus.ENABLED)
        self.repo.save(p2)
        plugins = self.repo.find_all()
        assert len(plugins) == 2

    def test_delete(self) -> None:
        self.repo.save(self.pkg)
        self.repo.delete("p1")
        assert self.repo.find_by_id("p1") is None

    def test_delete_nonexistent(self) -> None:
        self.repo.delete("nonexistent")

    def test_update_status(self) -> None:
        self.repo.save(self.pkg)
        self.repo.update_status("p1", PluginInstallStatus.ENABLED)
        updated = self.repo.find_by_id("p1")
        assert updated is not None
        assert updated.status == PluginInstallStatus.ENABLED

    def test_update_health(self) -> None:
        self.repo.save(self.pkg)
        self.repo.update_health("p1", PluginHealth.FAILED.value, "Something went wrong")
        updated = self.repo.find_by_id("p1")
        assert updated is not None
        assert updated.health == PluginHealth.FAILED
        assert updated.error_message == "Something went wrong"
