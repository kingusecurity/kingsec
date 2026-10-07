"""Presence and syntax checks for the repo-root installer scripts.

``kingsec-setup.sh`` / ``kingsec-start.sh`` are the first thing a new
operator touches; a missing file, a lost executable bit, or a shell
syntax error is a failed first impression. These tests are cheap and
run everywhere — the syntax check is skipped only where bash itself is
unavailable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ("kingsec-setup.sh", "kingsec-start.sh")


@pytest.mark.parametrize("script", SCRIPTS)
def test_installer_script_exists_and_is_executable(script: str) -> None:
    path = REPO_ROOT / script
    assert path.is_file(), f"{script} is missing from the repo root"
    assert os.access(path, os.X_OK), f"{script} is not executable"


@pytest.mark.parametrize("script", SCRIPTS)
def test_installer_script_passes_bash_syntax_check(script: str) -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash not available on this platform")
    result = subprocess.run(
        [bash, "-n", str(REPO_ROOT / script)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
