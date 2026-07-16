"""The Trivy implementation of the application ``ScannerPort``.

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

from .errors import ScannerExecutionError
from .runner import CommandRunner, SubprocessCommandRunner
from .trivy_parser import parse_trivy_json

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import TrivySettings

_logger = get_logger("kingsec.infrastructure.scanner")


class TrivyScannerAdapter(ScannerPort):
    """Runs Trivy against a target and returns domain findings."""

    def __init__(
        self,
        settings: "TrivySettings",
        runner: CommandRunner | None = None,
    ) -> None:
        self._settings = settings
        self._runner: CommandRunner = runner or SubprocessCommandRunner()

    def scan(self, target: Target) -> Sequence[Finding]:
        """Scan ``target`` with Trivy and return the findings discovered."""
        args = self._build_args(target)

        _logger.info(
            "trivy scan started",
            target=target.value,
            binary=self._settings.binary_path,
            scan_type=self._settings.scan_type,
        )
        result = self._runner.run(args, timeout=self._settings.timeout_seconds)

        if result.returncode != 0:
            raise ScannerExecutionError(
                f"trivy exited with code {result.returncode}",
                context={
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip()[:500],
                    "target": target.value,
                },
            )

        findings = parse_trivy_json(result.stdout)
        _logger.info(
            "trivy scan completed",
            target=target.value,
            findings=len(findings),
            duration_seconds=round(result.duration_seconds, 3),
        )
        return findings

    def _build_args(self, target: Target) -> list[str]:
        """Assemble the Trivy argument vector.

        Filesystem: ``trivy fs --format json <target>``
        Container:  ``trivy image --format json <target>``
        """
        settings = self._settings
        args: list[str] = [
            settings.binary_path,
            settings.scan_type,
            *settings.scan_args,
            "--format",
            "json",
            target.value,
        ]
        return args
