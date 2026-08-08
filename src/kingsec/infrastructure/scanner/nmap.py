"""The Nmap implementation of the application ``ScannerPort``.

Composes a safe argument list from configuration, runs it through a
``CommandRunner``, translates failures into ``ScannerError``, and parses the
XML output into domain ``Finding`` objects.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from kingsec.application import ScannerPort
from kingsec.domain import Finding, Target
from kingsec.infrastructure.logging import get_logger

from .errors import ScannerExecutionError
from .nmap_parser import parse_nmap_xml
from .runner import CommandRunner, SubprocessCommandRunner

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import NmapSettings

_logger = get_logger("kingsec.infrastructure.scanner")


class NmapScannerAdapter(ScannerPort):
    """Runs Nmap against a target and returns domain findings."""

    def __init__(
        self,
        settings: NmapSettings,
        runner: CommandRunner | None = None,
    ) -> None:
        self._settings = settings
        self._runner: CommandRunner = runner or SubprocessCommandRunner()

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        """This adapter only ever runs Nmap - no target-type filtering here."""
        return {"nmap": "Nmap"}

    def scan(self, target: Target, scanner_ids: Sequence[str] | None = None) -> Sequence[Finding]:
        """Scan ``target`` with Nmap and return the findings discovered."""
        if scanner_ids is not None and "nmap" not in scanner_ids:
            return ()
        args = self._build_args(target)

        _logger.info(
            "nmap scan started",
            target=target.value,
            binary=self._settings.binary_path,
        )
        result = self._runner.run(args, timeout=self._settings.timeout_seconds)

        findings = parse_nmap_xml(result.stdout)

        if result.returncode != 0 and not findings:
            raise ScannerExecutionError(
                f"nmap exited with code {result.returncode}",
                context={
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip()[:500],
                    "target": target.value,
                },
            )
        _logger.info(
            "nmap scan completed",
            target=target.value,
            findings=len(findings),
            duration_seconds=round(result.duration_seconds, 3),
        )
        return findings

    def _build_args(self, target: Target) -> list[str]:
        """Assemble the Nmap argument vector.

        Always outputs XML to stdout (-oX -) so the parser can consume it.
        """
        settings = self._settings
        args: list[str] = [
            settings.binary_path,
            *settings.scan_args,
            "-oX",
            "-",
            target.value,
        ]
        return args
