from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from kingsec.application.ports.outbound import PluginInstallerPort
from kingsec.domain.plugin_package import PluginManifest


class PathTraversalError(ValueError):
    """Raised when an archive entry attempts path traversal."""


def _sanitise_archive_path(dest: str, entry_path: str) -> str:
    """Resolve *entry_path* inside *dest* and reject any traversal attempt.

    Returns the resolved absolute path on success.

    Raises:
        PathTraversalError: If the entry path would escape *dest* (e.g.
            ``../``, absolute paths, Windows drive letters, symlink escapes).
    """
    dest_resolved = Path(dest).resolve()
    entry_resolved = (dest_resolved / entry_path).resolve()

    # Reject absolute entry paths (e.g. /etc/passwd)
    if os.path.isabs(entry_path):
        raise PathTraversalError(f"Archive entry {entry_path!r} is an absolute path")

    # Reject Windows drive paths
    entry_path_upper = entry_path.upper()
    if ":" in entry_path_upper and any(
        entry_path_upper.startswith(d) for d in [chr(c) + ":" for c in range(ord("A"), ord("Z") + 1)]
    ):
        raise PathTraversalError(f"Archive entry {entry_path!r} contains a Windows drive path")

    # Reject entries that escape the destination directory.
    # Use is_relative_to (Python 3.9+) which handles prefix collisions correctly
    # (e.g. /plugins/foobar vs /plugins/foo) — unlike a bare startswith check.
    if not entry_resolved.is_relative_to(dest_resolved):
        raise PathTraversalError(f"Archive entry {entry_path!r} would escape destination {dest!r}")

    return str(entry_resolved)


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
            for entry in zf.infolist():
                safe_path = _sanitise_archive_path(target, entry.filename)
                if entry.is_dir():
                    os.makedirs(safe_path, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(safe_path), exist_ok=True)
                    with zf.open(entry) as src, open(safe_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)
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
