"""The Gobuster implementation of the application ``ScannerPort``.

Composes a safe argument list from configuration, runs it through a
``CommandRunner``, translates failures into ``ScannerError``, and parses the
text output into domain ``Finding`` objects.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from kingsec.application import ScannerPort
from kingsec.domain import Finding, Target
from kingsec.infrastructure.logging import get_logger

from .errors import NONZERO_EXIT_USER_MESSAGE, WORDLIST_MISSING_USER_MESSAGE, ScannerExecutionError
from .gobuster_parser import parse_gobuster_output
from .runner import CommandRunner, SubprocessCommandRunner

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import GobusterSettings

_logger = get_logger("kingsec.infrastructure.scanner")


class GobusterScannerAdapter(ScannerPort):
    """Runs Gobuster against a target and returns domain findings."""

    def __init__(
        self,
        settings: GobusterSettings,
        runner: CommandRunner | None = None,
    ) -> None:
        self._settings = settings
        self._runner: CommandRunner = runner or SubprocessCommandRunner()

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        """This adapter only ever runs Gobuster - no target-type filtering here."""
        return {"gobuster": "Gobuster"}

    def scan(self, target: Target, scanner_ids: Sequence[str] | None = None) -> Sequence[Finding]:
        """Scan ``target`` with Gobuster and return the findings discovered."""
        if scanner_ids is not None and "gobuster" not in scanner_ids:
            return ()
        self._validate_config()
        args = self._build_args(target)

        _logger.info(
            "gobuster scan started",
            target=target.value,
            binary=self._settings.binary_path,
        )
        result = self._runner.run(args, timeout=self._settings.timeout_seconds)

        findings = parse_gobuster_output(result.stdout)

        if result.returncode != 0 and not findings:
            raise ScannerExecutionError(
                f"gobuster exited with code {result.returncode}",
                context={
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip()[:500],
                    "target": target.value,
                },
                user_message=NONZERO_EXIT_USER_MESSAGE,
            )
        _logger.info(
            "gobuster scan completed",
            target=target.value,
            findings=len(findings),
            duration_seconds=round(result.duration_seconds, 3),
        )
        return findings

    def _validate_config(self) -> None:
        """Fail fast if required configuration is missing."""
        if not self._settings.wordlist.strip():
            raise ScannerExecutionError(
                "gobuster wordlist is not configured",
                context={"binary": self._settings.binary_path},
                user_message=WORDLIST_MISSING_USER_MESSAGE,
            )

    def _build_args(self, target: Target) -> list[str]:
        """Assemble the Gobuster argument vector.

        Gobuster uses ``gobuster dir -u <target> -w <wordlist>`` for
        directory enumeration.
        """
        settings = self._settings
        args: list[str] = [
            settings.binary_path,
            "dir",
            *settings.scan_args,
            "-u",
            target.value,
            "-w",
            settings.wordlist,
        ]
        return args
