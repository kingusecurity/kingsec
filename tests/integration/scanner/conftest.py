"""Fixtures for scanner integration tests."""

from __future__ import annotations

import io
import platform
import stat
import sys
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
    "findings": (f"import sys\nsys.stdout.write({_SAMPLE_JSONL!r})\nsys.exit(0)\n"),
    "empty": "import sys\nsys.exit(0)\n",
    "error": ("import sys\nsys.stderr.write('fatal: could not load templates\\n')\nsys.exit(2)\n"),
    "slow": "import time\ntime.sleep(30)\n",
}


@pytest.fixture(autouse=True)
def quiet_logging() -> None:
    configure_logging(LoggingSettings(level="ERROR", json_format=True), stream=io.StringIO())


@pytest.fixture
def make_fake_nuclei(tmp_path: Path) -> Callable[[str], Path]:
    """Return a factory that writes an executable fake-nuclei script for a mode."""

    def _make(mode: str) -> Path:
        script = tmp_path / f"fake_nuclei_{mode}.py"
        script.write_text("#!/usr/bin/env python3\n" + _SCRIPTS[mode])
        if platform.system() == "Windows":
            # Windows cannot execute .py files directly; create a .cmd wrapper.
            cmd = tmp_path / f"fake_nuclei_{mode}.cmd"
            cmd.write_text(f'"{sys.executable}" "{script}" %*\n')
            return cmd
        script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IRUSR)
        return script

    return _make
