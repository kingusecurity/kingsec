"""Task 5B Priority 2: the timeout must bound the WHOLE process tree, not
just the one process Python holds a handle to.

The parent/grandchild reproduction below is lifted directly from the Task
5 hang investigation. Verified failing against the pre-fix
SubprocessCommandRunner: this exact scenario made
``runner.run(timeout=3.0)`` block for 120.2 seconds - however long the
grandchild's own unrelated sleep took, not the configured timeout -
because ``Popen.kill()``/``TerminateProcess`` only ever terminated the
one process Python held a handle to, while the grandchild kept the
inherited stdout/stderr pipe open, blocking the post-timeout drain read
indefinitely. These tests now pass because the killed process's entire
tree, not just itself, is guaranteed dead.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from kingsec.infrastructure.scanner.errors import ScannerExecutionError
from kingsec.infrastructure.scanner.runner import SubprocessCommandRunner

_GRANDCHILD_SLEEP_SECONDS = 120


def _write_parent_and_grandchild(tmp_path: Path) -> tuple[Path, Path]:
    """A parent that spawns a plain (non-detached) child and waits on it -
    exactly the shape of an install4j-style native launcher (ZAP.exe)
    starting its real worker (javaw.exe) as a child and waiting for it."""
    grandchild = tmp_path / "grandchild.py"
    grandchild.write_text(
        "import sys\nimport time\n"
        "sys.stdout.write('GRANDCHILD STARTED\\n')\nsys.stdout.flush()\n"
        f"time.sleep({_GRANDCHILD_SLEEP_SECONDS})\n"
    )
    parent = tmp_path / "parent.py"
    parent.write_text(
        "import subprocess\nimport sys\n"
        f"gc = subprocess.Popen([sys.executable, {str(grandchild)!r}])\n"
        "sys.stdout.write('PARENT: spawned grandchild pid ' + str(gc.pid) + '\\n')\n"
        "sys.stdout.flush()\n"
        "gc.wait()\n"
    )
    return parent, grandchild


def _process_table_snapshot() -> str:
    """Best-effort process-table snapshot, cross-platform."""
    if sys.platform == "win32":
        out = subprocess.run(
            ["wmic", "process", "where", "name='python.exe'", "get", "ProcessId,CommandLine"],  # noqa: S607
            capture_output=True,
            text=True,
        )
    else:
        out = subprocess.run(
            ["ps", "-eo", "pid,args"], capture_output=True, text=True  # noqa: S607
        )
    return out.stdout


class TestProcessTreeGuard:
    def test_timeout_returns_quickly_not_after_the_grandchilds_own_sleep(self, tmp_path: Path) -> None:
        """Verified failing against the pre-fix code: this returned after
        120.2s (however long the grandchild's own unrelated sleep took),
        not the configured 3s timeout. Must now return within a few
        seconds, regardless of how long the orphaned grandchild would
        otherwise have kept running."""
        parent, _grandchild = _write_parent_and_grandchild(tmp_path)
        runner = SubprocessCommandRunner()

        t0 = time.monotonic()
        with pytest.raises(ScannerExecutionError, match="timed out"):
            runner.run([sys.executable, str(parent)], timeout=3.0)
        elapsed = time.monotonic() - t0

        assert elapsed < 15, f"timeout did not bound the process tree - took {elapsed:.1f}s"

    def test_no_grandchild_process_survives_the_timeout(self, tmp_path: Path) -> None:
        """Assert on the process table, not the exception - the whole
        point of the fix is that nothing is left running afterward,
        which the exception alone cannot prove."""
        parent, grandchild = _write_parent_and_grandchild(tmp_path)
        runner = SubprocessCommandRunner()
        marker = str(grandchild)

        with pytest.raises(ScannerExecutionError, match="timed out"):
            runner.run([sys.executable, str(parent)], timeout=3.0)

        time.sleep(1)  # let the OS settle the kill before snapshotting
        survivors = _process_table_snapshot()
        assert marker not in survivors, f"grandchild process survived the timeout:\n{survivors}"


class TestStdinIsAlwaysClosed:
    def test_scanner_reading_stdin_gets_eof_immediately(self, tmp_path: Path) -> None:
        """A scanner that unexpectedly tries to read stdin (a first-run
        prompt, an "are you sure?" confirmation) must get immediate EOF,
        not a live connection to whatever KingSec's own stdin happens to
        be."""
        script = tmp_path / "reads_stdin.py"
        script.write_text(
            "import sys\ndata = sys.stdin.read()\nsys.stdout.write('READ ' + str(len(data)) + ' BYTES\\n')\n"
        )
        runner = SubprocessCommandRunner()

        t0 = time.monotonic()
        result = runner.run([sys.executable, str(script)], timeout=5.0)
        elapsed = time.monotonic() - t0

        assert elapsed < 5, "stdin was not closed - the script blocked waiting for input"
        assert "READ 0 BYTES" in result.stdout


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: verifies start_new_session made the child its own session leader",
)
class TestPosixStartNewSession:
    def test_child_becomes_its_own_session_leader(self, tmp_path: Path) -> None:
        """This dev machine is Windows - this test runs for real in CI's
        Linux container (pyproject.toml's mypy platform pin documents the
        same Linux target), not here. Skipped rather than faked so the
        POSIX path is genuinely exercised somewhere, not just asserted
        untested."""
        script = tmp_path / "report_sid.py"
        script.write_text("import os\nimport sys\nsys.stdout.write(str(os.getsid(0)) + ' ' + str(os.getpid()) + '\\n')\n")
        runner = SubprocessCommandRunner()

        result = runner.run([sys.executable, str(script)], timeout=5.0)

        child_sid_str, child_pid_str = result.stdout.split()
        assert int(child_sid_str) == int(child_pid_str), (
            "child was not its own session leader - start_new_session did not take effect"
        )
