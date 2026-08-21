"""Hatch build hook: strip any untracked Alembic revision file from a built
wheel, independent of whatever generated it or what it is named.

`pyproject.toml`'s `include`/`exclude` and `.gitignore`-derived excludes are
all filesystem/pattern-based — verified empirically (Phase 16 report §6)
that they cannot correctly distinguish an untracked stray file from a
legitimately committed migration that happens to share the same
``*__no_changes.py`` naming pattern (seven of the tracked revisions do).
Only ``git ls-files`` reflects true tracked status, so this hook checks the
already-built wheel against it directly and removes anything that doesn't
belong, rather than trying to get the file-selection glob to do it.

Deliberately fails open, not closed: if this is not a git checkout (e.g.
building from an sdist with no ``.git``, as the Docker image's builder
stage does after its own `git archive` step already guaranteed a clean
source — see Dockerfile), there is nothing to check against, so the hook
no-ops rather than breaking an otherwise-valid build. That is safe here
specifically because every path that lacks `.git` in this project already
has its own independent guarantee of a clean source tree.
"""

from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class StripUntrackedAlembicVersionsHook(BuildHookInterface):  # type: ignore[type-arg]
    PLUGIN_NAME = "strip-untracked-alembic-versions"

    def finalize(self, _version: str, _build_data: dict[str, Any], artifact_path: str) -> None:
        if not artifact_path.endswith(".whl"):
            return

        tracked_basenames = self._tracked_alembic_version_basenames()
        if tracked_basenames is None:
            return  # Not a git checkout - nothing to verify against.

        with zipfile.ZipFile(artifact_path) as zf:
            names = zf.namelist()

        stray = [
            n
            for n in names
            if "/alembic/versions/" in n
            and n.endswith(".py")
            and Path(n).name not in tracked_basenames
        ]
        if not stray:
            return

        self.app.display_warning(
            f"stripping {len(stray)} untracked alembic revision file(s) from the wheel: {stray}"
        )
        tmp_path = artifact_path + ".tmp"
        with (
            zipfile.ZipFile(artifact_path) as src,
            zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as dst,
        ):
            for item in src.infolist():
                if item.filename in stray:
                    continue
                dst.writestr(item, src.read(item.filename))
        Path(tmp_path).replace(artifact_path)

    def _tracked_alembic_version_basenames(self) -> set[str] | None:
        try:
            result = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, build-time only
                ["git", "ls-files", "src/kingsec/alembic/versions/"],  # noqa: S607
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return {Path(line).name for line in result.stdout.splitlines() if line.strip()}
