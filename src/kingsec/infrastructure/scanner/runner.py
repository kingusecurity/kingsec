"""The process-execution boundary for the scanner.

This is the only module that touches ``subprocess``. It executes a pre-built
argument LIST (never a shell string) so no shell can interpret metacharacters in
a target — the essential defence against command injection. A ``CommandRunner``
Protocol lets tests inject a fake so the adapter can be unit-tested without any
real binary.
"""

from __future__ import annotations

import subprocess  # noqa: S404 - used safely: arg list, shell=False, with timeout
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from kingsec.infrastructure.logging import get_logger

from .errors import ScannerExecutionError

_logger = get_logger("kingsec.infrastructure.scanner")


@dataclass(frozen=True)
class CommandResult:
    """The captured outcome of running an external command."""

    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float


class CommandRunner(Protocol):
    """Runs an argument list with a timeout and returns the captured result."""

    def run(self, args: Sequence[str], *, timeout: float) -> CommandResult:
        """Execute ``args`` and return its result.

        Raises:
            ScannerExecutionError: If the binary is missing or the run times out.
        """
        ...


class SubprocessCommandRunner:
    """The production ``CommandRunner`` backed by :mod:`subprocess`.

    Security properties (do not weaken):
        * ``shell=False`` — the argument list is passed straight to ``execvp``;
          no shell parses it, so target strings cannot inject commands.
        * A mandatory ``timeout`` bounds execution so a hung scan cannot wedge
          the process.
        * stdout/stderr are captured (not inherited), so scanner output never
          leaks to the console and can be parsed deterministically.
    """

    def run(self, args: Sequence[str], *, timeout: float) -> CommandResult:
        """Run the command list, capturing output and timing it.

        Args:
            args: The full argument vector, e.g. ``["nuclei", "-u", target, ...]``.
                The first element is the executable; the rest are arguments.
            timeout: Hard wall-clock limit in seconds.

        Returns:
            The captured :class:`CommandResult`.

        Raises:
            ScannerExecutionError: If the executable is not found or the run
                exceeds ``timeout``.
        """

        argv = list(args)
        start = time.monotonic()
        try:
            completed = subprocess.run(  # noqa: S603 - list args, shell=False, trusted binary
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ScannerExecutionError(
                f"scanner binary not found: {argv[0]!r}",
                context={"binary": argv[0]},
                cause=exc,
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ScannerExecutionError(
                f"scan timed out after {timeout:.0f}s",
                context={"timeout_seconds": timeout},
                cause=exc,
            ) from exc

        duration = time.monotonic() - start
        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            duration_seconds=duration,
        )
