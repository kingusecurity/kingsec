from __future__ import annotations

import json
import os
import tempfile
import zipfile

from kingsec.domain.plugin_package import PluginManifest, PluginVersion
from kingsec.infrastructure.plugin.installer import PluginInstaller


class TestPluginInstaller:
    def setup_method(self) -> None:
        self.base_dir = tempfile.mkdtemp()
        self.installer = PluginInstaller(base_dir=self.base_dir)

    def _create_plugin_zip(self, plugin_id: str = "test-plugin") -> str:
        fd, path = tempfile.mkstemp(suffix=".zip")
        with os.fdopen(fd, "wb") as f:
            with zipfile.ZipFile(f, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("manifest.json", json.dumps({"id": plugin_id, "name": "Test", "version": "1.0.0"}))
                zf.writestr("main.py", "print('hello')")
        return path

    def test_install_creates_directory(self) -> None:
        manifest = PluginManifest(id="test-plugin", name="Test", version=PluginVersion(1, 0, 0))
        path = self._create_plugin_zip()
        try:
            target = self.installer.install(path, manifest)
            assert os.path.isdir(target)
            assert os.path.isfile(os.path.join(target, "main.py"))
        finally:
            os.unlink(path)

    def test_uninstall_removes_directory(self) -> None:
        manifest = PluginManifest(id="test-plugin", name="Test", version=PluginVersion(1, 0, 0))
        path = self._create_plugin_zip()
        try:
            self.installer.install(path, manifest)
            self.installer.uninstall("test-plugin")
            assert not os.path.isdir(os.path.join(self.base_dir, "test-plugin"))
        finally:
            os.unlink(path)

    def test_rollback_with_backup(self) -> None:
        manifest = PluginManifest(id="test-plugin", name="Test", version=PluginVersion(1, 0, 0))
        path = self._create_plugin_zip()
        try:
            target = self.installer.install(path, manifest)
            bak = target + ".bak"
            if os.path.exists(bak):
                import shutil
                shutil.rmtree(bak)
            os.rename(target, bak)
            result = self.installer.rollback("test-plugin", target)
            assert result is not None
            assert os.path.isdir(result)
        finally:
            os.unlink(path)

    def test_rollback_no_backup(self) -> None:
        result = self.installer.rollback("nonexistent", "/tmp/noexist")
        assert result is None
