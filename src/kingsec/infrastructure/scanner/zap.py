"""The OWASP ZAP implementation of the application ``ScannerPort``.

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

from .errors import NONZERO_EXIT_USER_MESSAGE, ScannerExecutionError
from .runner import CommandRunner, SubprocessCommandRunner
from .zap_parser import parse_zap_json

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import ZapSettings

_logger = get_logger("kingsec.infrastructure.scanner")


class ZapScannerAdapter(ScannerPort):
    """Runs OWASP ZAP against a target and returns domain findings."""

    def __init__(
        self,
        settings: ZapSettings,
        runner: CommandRunner | None = None,
    ) -> None:
        self._settings = settings
        self._runner: CommandRunner = runner or SubprocessCommandRunner()

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        """This adapter only ever runs OWASP ZAP - no target-type filtering here."""
        return {"zap": "OWASP ZAP"}

    def scan(self, target: Target, scanner_ids: Sequence[str] | None = None) -> Sequence[Finding]:
        """Scan ``target`` with ZAP and return the findings discovered."""
        if scanner_ids is not None and "zap" not in scanner_ids:
            return ()
        args = self._build_args(target)

        _logger.info(
            "zap scan started",
            target=target.value,
            binary=self._settings.binary_path,
        )
        result = self._runner.run(args, timeout=self._settings.timeout_seconds)

        findings = parse_zap_json(result.stdout)

        if result.returncode != 0 and not findings:
            raise ScannerExecutionError(
                f"zap exited with code {result.returncode}",
                context={
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip()[:500],
                    "target": target.value,
                },
                user_message=NONZERO_EXIT_USER_MESSAGE,
            )
        _logger.info(
            "zap scan completed",
            target=target.value,
            findings=len(findings),
            duration_seconds=round(result.duration_seconds, 3),
        )
        return findings

    def _build_args(self, target: Target) -> list[str]:
        """Assemble the ZAP argument vector.

        ZAP quick scan: ``zap -quickurl <target> -quickout json``
        """
        settings = self._settings
        args: list[str] = [
            settings.binary_path,
            *settings.scan_args,
            "-quickurl",
            target.value,
            "-quickout",
            "json",
        ]
        return args
