"""The process-execution boundary for the scanner.

This is the only module that touches ``subprocess``. It executes a pre-built
argument LIST (never a shell string) so no shell can interpret metacharacters in
a target — the essential defence against command injection. A ``CommandRunner``
Protocol lets tests inject a fake so the adapter can be unit-tested without any
real binary.
"""

from __future__ import annotations

import subprocess  # nosec B404 — scanner binaries are configured by admin, validated, and run with shell=False + timeout
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from kingsec.infrastructure.logging import get_logger

from .errors import BINARY_ABSENT_USER_MESSAGE, ScannerExecutionError

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
            completed = subprocess.run(  # nosec B603 — argv is validated, shell=False, timeout is set, executable is allow-listed
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
                user_message=BINARY_ABSENT_USER_MESSAGE,
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ScannerExecutionError(
                f"scan timed out after {timeout:.0f}s",
                context={"timeout_seconds": timeout},
                cause=exc,
                # The configured timeout duration is product configuration,
                # not infrastructure detail (unlike a path or hostname) - an
                # admin-set number of seconds, safely interpolatable and
                # directly actionable ("raise it if this target is
                # legitimately slow"). See Phase 08 report §2/§6 for the
                # full reasoning behind this specific judgement call.
                user_message=(
                    f"The scan did not complete within the configured {timeout:.0f}-second "
                    "timeout. If this is expected for the target, increase the scanner's "
                    "timeout in its configuration."
                ),
            ) from exc

        duration = time.monotonic() - start
        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            duration_seconds=duration,
        )
