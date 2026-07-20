from __future__ import annotations

import os
import shutil
import tempfile

from kingsec.application.ports.outbound import PluginInstallerPort
from kingsec.domain.plugin_package import PluginManifest


class PluginInstaller(PluginInstallerPort):
    """Filesystem-based plugin installation manager.

    Never executes uploaded code — only extracts archives and copies files.
    """

    def __init__(self, base_dir: str | None = None) -> None:
        self._base_dir = base_dir or os.path.join(tempfile.gettempdir(), "kingsec", "plugins")

    def _plugin_dir(self, plugin_id: str) -> str:
        return os.path.join(self._base_dir, plugin_id)

    def install(self, package_path: str, manifest: PluginManifest) -> str:
        import zipfile
        target = self._plugin_dir(manifest.id)
        if os.path.exists(target):
            backup = target + ".bak"
            if os.path.exists(backup):
                shutil.rmtree(backup)
            os.rename(target, backup)
        os.makedirs(target, exist_ok=True)
        with zipfile.ZipFile(package_path, "r") as zf:
            zf.extractall(target)
        return target

    def uninstall(self, plugin_id: str) -> None:
        target = self._plugin_dir(plugin_id)
        if os.path.exists(target):
            shutil.rmtree(target)

    def rollback(self, plugin_id: str, backup_path: str) -> str | None:
        target = self._plugin_dir(plugin_id)
        backup = target + ".bak"
        if not os.path.exists(backup):
            return None
        if os.path.exists(target):
            shutil.rmtree(target)
        os.rename(backup, target)
        return target
