"""The OWASP Amass implementation of the application ``ScannerPort``.

Composes a safe argument list from configuration, runs it through a
``CommandRunner``, translates failures into ``ScannerError``, and parses the
JSON output into domain ``Finding`` objects.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from kingsec.application import ScannerPort
from kingsec.domain import Finding, Target
from kingsec.infrastructure.logging import get_logger

from .amass_parser import parse_amass_json
from .errors import ScannerExecutionError
from .runner import CommandRunner, SubprocessCommandRunner

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import AmassSettings

_logger = get_logger("kingsec.infrastructure.scanner")


class AmassScannerAdapter(ScannerPort):
    """Runs OWASP Amass against a target and returns domain findings."""

    def __init__(
        self,
        settings: AmassSettings,
        runner: CommandRunner | None = None,
    ) -> None:
        self._settings = settings
        self._runner: CommandRunner = runner or SubprocessCommandRunner()

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        """This adapter only ever runs Amass - no target-type filtering here."""
        return {"amass": "Amass"}

    def scan(self, target: Target, scanner_ids: Sequence[str] | None = None) -> Sequence[Finding]:
        """Scan ``target`` with Amass and return the findings discovered."""
        if scanner_ids is not None and "amass" not in scanner_ids:
            return ()
        args = self._build_args(target)

        _logger.info(
            "amass scan started",
            target=target.value,
            binary=self._settings.binary_path,
        )
        result = self._runner.run(args, timeout=self._settings.timeout_seconds)

        findings = parse_amass_json(result.stdout)

        if result.returncode != 0 and not findings:
            raise ScannerExecutionError(
                f"amass exited with code {result.returncode}",
                context={
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip()[:500],
                    "target": target.value,
                },
            )
        _logger.info(
            "amass scan completed",
            target=target.value,
            findings=len(findings),
            duration_seconds=round(result.duration_seconds, 3),
        )
        return findings

    def _build_args(self, target: Target) -> list[str]:
        """Assemble the Amass argument vector.

        Amass uses ``amass enum -passive -json - -d <target>`` for
        passive subdomain enumeration.
        """
        settings = self._settings
        args: list[str] = [
            settings.binary_path,
            "enum",
            *settings.scan_args,
            "-passive",
            "-json",
            "-",
            "-d",
            target.value,
        ]
        return args
