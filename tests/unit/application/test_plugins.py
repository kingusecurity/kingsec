from __future__ import annotations

import json
import os
import tempfile
import zipfile

import pytest

from kingsec.application.errors import (
    PluginDependencyError,
    PluginNotFoundError,
    PluginValidationError,
)
from kingsec.application.use_cases.plugins import (
    CheckPluginUpdates,
    DisablePlugin,
    EnablePlugin,
    ExportPlugin,
    GetPlugin,
    ImportPlugin,
    InstallPlugin,
    ListPlugins,
    RollbackPlugin,
    UninstallPlugin,
    UpdatePlugin,
    ValidatePlugin,
)
from kingsec.domain.plugin_package import (
    PluginDependency,
    PluginHealth,
    PluginInstallStatus,
    PluginManifest,
    PluginPackage,
    PluginVersion,
)
from kingsec.infrastructure.plugin.installer import PluginInstaller
from kingsec.infrastructure.plugin.repository import InMemoryPluginRepository
from kingsec.infrastructure.plugin.validator import PluginValidator


def _create_plugin_zip(manifest: dict | None = None) -> str:
    fd, path = tempfile.mkstemp(suffix=".zip")
    with os.fdopen(fd, "wb") as f, zipfile.ZipFile(f, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "manifest.json",
            json.dumps(
                manifest
                or {
                    "id": "test-plugin",
                    "name": "Test Plugin",
                    "version": "1.0.0",
                    "author": "KingSec",
                    "license": "MIT",
                    "description": "Test plugin",
                }
            ),
        )
        zf.writestr("main.py", "print('hello')")
    return path


def _create_manifest(overrides: dict | None = None) -> PluginManifest:
    data = {
        "id": "test-plugin",
        "name": "Test Plugin",
        "version": PluginVersion(1, 0, 0),
        "author": "KingSec",
        "license": "MIT",
        "description": "Test plugin description",
        "entry_point": "main.py",
        "tags": ("security",),
    }
    if overrides:
        data.update(overrides)
    return PluginManifest(**data)


class TestInstallPlugin:
    def setup_method(self) -> None:
        self.repo = InMemoryPluginRepository()
        self.installer = PluginInstaller()
        self.validator = PluginValidator()
        self.uc = InstallPlugin(self.repo, self.installer, self.validator)

    def test_install_success(self) -> None:
        manifest = _create_manifest()
        path = _create_plugin_zip()
        try:
            pkg = self.uc.execute(path, manifest)
            assert pkg.id == "test-plugin"
            assert pkg.status == PluginInstallStatus.INSTALLED
            assert pkg.health == PluginHealth.HEALTHY
        finally:
            os.unlink(path)

    def test_install_already_installed(self) -> None:
        manifest = _create_manifest()
        path = _create_plugin_zip()
        try:
            self.uc.execute(path, manifest)
            with pytest.raises(ValueError, match="already installed"):
                self.uc.execute(path, manifest)
        finally:
            os.unlink(path)

    def test_install_with_dependencies(self) -> None:
        manifest = _create_manifest(
            {
                "dependencies": (PluginDependency("missing-dep", ">=1.0.0"),),
            }
        )
        path = _create_plugin_zip()
        try:
            with pytest.raises(PluginDependencyError):
                self.uc.execute(path, manifest)
        finally:
            os.unlink(path)


class TestUninstallPlugin:
    def setup_method(self) -> None:
        self.repo = InMemoryPluginRepository()
        self.installer = PluginInstaller()
        self.validator = PluginValidator()
        self.install_uc = InstallPlugin(self.repo, self.installer, self.validator)
        self.uc = UninstallPlugin(self.repo, self.installer)

    def test_uninstall_success(self) -> None:
        manifest = _create_manifest()
        path = _create_plugin_zip()
        try:
            self.install_uc.execute(path, manifest)
            self.uc.execute("test-plugin")
            assert self.repo.find_by_id("test-plugin") is None
        finally:
            os.unlink(path)

    def test_uninstall_not_found(self) -> None:
        with pytest.raises(PluginNotFoundError):
            self.uc.execute("nonexistent")


class TestEnableDisablePlugin:
    def setup_method(self) -> None:
        self.repo = InMemoryPluginRepository()
        self.installer = PluginInstaller()
        self.validator = PluginValidator()
        self.install_uc = InstallPlugin(self.repo, self.installer, self.validator)
        manifest = _create_manifest()
        path = _create_plugin_zip()
        try:
            self.install_uc.execute(path, manifest)
        finally:
            os.unlink(path)

    def test_enable(self) -> None:
        uc = EnablePlugin(self.repo)
        pkg = uc.execute("test-plugin")
        assert pkg.status == PluginInstallStatus.ENABLED

    def test_disable(self) -> None:
        uc = DisablePlugin(self.repo)
        pkg = uc.execute("test-plugin")
        assert pkg.status == PluginInstallStatus.DISABLED

    def test_enable_not_found(self) -> None:
        uc = EnablePlugin(self.repo)
        with pytest.raises(PluginNotFoundError):
            uc.execute("nonexistent")


class TestUpdatePlugin:
    def setup_method(self) -> None:
        self.repo = InMemoryPluginRepository()
        self.installer = PluginInstaller()
        self.validator = PluginValidator()
        self.install_uc = InstallPlugin(self.repo, self.installer, self.validator)
        manifest = _create_manifest()
        path = _create_plugin_zip()
        try:
            self.install_uc.execute(path, manifest)
        finally:
            os.unlink(path)

    def test_update_success(self) -> None:
        uc = UpdatePlugin(self.repo, self.installer, self.validator)
        manifest_v2 = _create_manifest({"version": PluginVersion(2, 0, 0)})
        path = _create_plugin_zip(
            {
                "id": "test-plugin",
                "name": "Test Plugin",
                "version": "2.0.0",
                "author": "KS",
                "license": "MIT",
                "description": "",
            }
        )
        try:
            pkg = uc.execute("test-plugin", path, manifest_v2)
            assert str(pkg.manifest.version) == "2.0.0"
        finally:
            os.unlink(path)

    def test_update_not_found(self) -> None:
        uc = UpdatePlugin(self.repo, self.installer, self.validator)
        manifest = _create_manifest()
        path = _create_plugin_zip()
        try:
            with pytest.raises(PluginNotFoundError):
                uc.execute("nonexistent", path, manifest)
        finally:
            os.unlink(path)


class TestRollbackPlugin:
    def setup_method(self) -> None:
        self.repo = InMemoryPluginRepository()
        self.installer = PluginInstaller()
        self.validator = PluginValidator()
        self.uc = RollbackPlugin(self.repo, self.installer)

    def test_rollback_not_installed(self) -> None:
        with pytest.raises(PluginNotFoundError):
            self.uc.execute("nonexistent")


class TestValidatePlugin:
    def setup_method(self) -> None:
        self.validator = PluginValidator()
        self.uc = ValidatePlugin(self.validator)

    def test_validate_valid_plugin(self) -> None:
        path = _create_plugin_zip()
        try:
            result = self.uc.execute(path)
            assert result["valid"] is True
        finally:
            os.unlink(path)

    def test_validate_invalid_zip(self) -> None:
        fd, path = tempfile.mkstemp(suffix=".zip")
        with os.fdopen(fd, "wb") as f:
            f.write(b"not a zip file")
        try:
            with pytest.raises(PluginValidationError):
                self.uc.execute(path)
        finally:
            os.unlink(path)

    def test_validate_missing_manifest(self) -> None:
        fd, path = tempfile.mkstemp(suffix=".zip")
        with os.fdopen(fd, "wb") as f, zipfile.ZipFile(f, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("some_file.txt", "hello")
        try:
            with pytest.raises(PluginValidationError, match="Missing manifest.json"):
                self.uc.execute(path)
        finally:
            os.unlink(path)


class TestListGetPlugins:
    def setup_method(self) -> None:
        self.repo = InMemoryPluginRepository()
        self.installer = PluginInstaller()
        self.validator = PluginValidator()
        self.install_uc = InstallPlugin(self.repo, self.installer, self.validator)

    def test_list_empty(self) -> None:
        uc = ListPlugins(self.repo)
        assert uc.execute() == []

    def test_list_with_plugins(self) -> None:
        manifest = _create_manifest()
        path = _create_plugin_zip()
        try:
            self.install_uc.execute(path, manifest)
            uc = ListPlugins(self.repo)
            plugins = uc.execute()
            assert len(plugins) == 1
            assert plugins[0].id == "test-plugin"
        finally:
            os.unlink(path)

    def test_get_plugin_found(self) -> None:
        manifest = _create_manifest()
        path = _create_plugin_zip()
        try:
            self.install_uc.execute(path, manifest)
            uc = GetPlugin(self.repo)
            p = uc.execute("test-plugin")
            assert p is not None
            assert p.id == "test-plugin"
        finally:
            os.unlink(path)

    def test_get_plugin_not_found(self) -> None:
        uc = GetPlugin(self.repo)
        assert uc.execute("nonexistent") is None


class TestExportPlugin:
    def setup_method(self) -> None:
        self.repo = InMemoryPluginRepository()
        self.uc = ExportPlugin(self.repo)

    def test_export_not_found(self) -> None:
        assert self.uc.execute("nonexistent") is None

    def test_export_success(self) -> None:
        manifest = _create_manifest()
        pkg = PluginPackage(id="test-plugin", manifest=manifest, status=PluginInstallStatus.INSTALLED)
        self.repo.save(pkg)
        data = self.uc.execute("test-plugin")
        assert data is not None
        import io
        import zipfile

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            assert "manifest.json" in zf.namelist()


class TestCheckPluginUpdates:
    def setup_method(self) -> None:
        self.repo = InMemoryPluginRepository()

    def test_check_updates_not_found(self) -> None:
        from kingsec.infrastructure.plugin.marketplace import MarketplaceClient

        uc = CheckPluginUpdates(self.repo, MarketplaceClient())
        with pytest.raises(PluginNotFoundError):
            uc.execute("nonexistent")


class TestImportPlugin:
    def setup_method(self) -> None:
        self.repo = InMemoryPluginRepository()
        self.installer = PluginInstaller()
        self.validator = PluginValidator()
        self.uc = ImportPlugin(self.repo, self.installer, self.validator)

    def test_import_success(self) -> None:
        path = _create_plugin_zip()
        try:
            pkg = self.uc.execute(path, "plugin.zip")
            assert pkg.id == "test-plugin"
            assert pkg.status == PluginInstallStatus.INSTALLED
        finally:
            os.unlink(path)

    def test_import_invalid_archive(self) -> None:
        fd, path = tempfile.mkstemp(suffix=".zip")
        with os.fdopen(fd, "wb") as f:
            f.write(b"garbage")
        try:
            with pytest.raises(PluginValidationError):
                self.uc.execute(path, "bad.zip")
        finally:
            os.unlink(path)
