"""Fixtures for scanner integration tests.

These tests exercise the REAL subprocess path via ``SubprocessCommandRunner``, so
we need a stand-in executable. ``make_fake_nuclei`` writes a small Python script
(with a shebang and the executable bit) that mimics the Nuclei CLI: it emits
canned JSONL, or sleeps, or exits non-zero, depending on the requested mode.
"""

from __future__ import annotations

import io
import os
import stat
from collections.abc import Callable
from pathlib import Path

import pytest

from kingsec.infrastructure.config.models import LoggingSettings
from kingsec.infrastructure.logging import configure_logging

_SAMPLE_JSONL = (
    '{"template-id":"CVE-2021-1","info":{"name":"Critical RCE",'
    '"severity":"critical","description":"remote code execution",'
    '"remediation":"apply vendor patch"},"type":"http",'
    '"matched-at":"http://10.0.0.5/vuln"}\n'
    '{"template-id":"missing-headers","info":{"name":"Missing CSP",'
    '"severity":"low"},"type":"http","host":"10.0.0.5"}\n'
)

_SCRIPTS: dict[str, str] = {
    # Emits two findings on stdout and exits 0.
    "findings": (
        "import sys\n"
        f"sys.stdout.write({_SAMPLE_JSONL!r})\n"
        "sys.exit(0)\n"
    ),
    # Emits nothing (no findings) and exits 0.
    "empty": "import sys\nsys.exit(0)\n",
    # Writes an error to stderr and exits non-zero.
    "error": (
        "import sys\n"
        "sys.stderr.write('fatal: could not load templates\\n')\n"
        "sys.exit(2)\n"
    ),
    # Sleeps longer than the test timeout to trigger a timeout.
    "slow": "import time\ntime.sleep(30)\n",
}


@pytest.fixture(autouse=True)
def quiet_logging() -> None:
    configure_logging(
        LoggingSettings(level="ERROR", json_format=True), stream=io.StringIO()
    )


@pytest.fixture
def make_fake_nuclei(tmp_path: Path) -> Callable[[str], Path]:
    """Return a factory that writes an executable fake-nuclei script for a mode."""

    def _make(mode: str) -> Path:
        script = tmp_path / f"fake_nuclei_{mode}.py"
        script.write_text("#!/usr/bin/env python3\n" + _SCRIPTS[mode])
        # Make it executable so it can be invoked directly as a "binary".
        script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IRUSR)
        return script

    return _make
