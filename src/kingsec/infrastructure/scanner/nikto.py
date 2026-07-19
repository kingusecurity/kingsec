"""The Nikto implementation of the application ``ScannerPort``.

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

from .errors import ScannerExecutionError
from .nikto_parser import parse_nikto_output
from .runner import CommandRunner, SubprocessCommandRunner

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import NiktoSettings

_logger = get_logger("kingsec.infrastructure.scanner")


class NiktoScannerAdapter(ScannerPort):
    """Runs Nikto against a target and returns domain findings."""

    def __init__(
        self,
        settings: NiktoSettings,
        runner: CommandRunner | None = None,
    ) -> None:
        self._settings = settings
        self._runner: CommandRunner = runner or SubprocessCommandRunner()

    def scan(self, target: Target) -> Sequence[Finding]:
        """Scan ``target`` with Nikto and return the findings discovered."""
        args = self._build_args(target)

        _logger.info(
            "nikto scan started",
            target=target.value,
            binary=self._settings.binary_path,
        )
        result = self._runner.run(args, timeout=self._settings.timeout_seconds)

        if result.returncode != 0:
            raise ScannerExecutionError(
                f"nikto exited with code {result.returncode}",
                context={
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip()[:500],
                    "target": target.value,
                },
            )

        findings = parse_nikto_output(result.stdout)
        _logger.info(
            "nikto scan completed",
            target=target.value,
            findings=len(findings),
            duration_seconds=round(result.duration_seconds, 3),
        )
        return findings

    def _build_args(self, target: Target) -> list[str]:
        """Assemble the Nikto argument vector.

        Nikto targets are specified with ``-h host``.
        """
        settings = self._settings
        args: list[str] = [
            settings.binary_path,
            *settings.scan_args,
            "-h",
            target.value,
        ]
        return args
