"""The ffuf implementation of the application ``ScannerPort``.

Composes a safe argument list from configuration, runs it through a
``CommandRunner``, translates failures into ``ScannerError``, and parses the
JSONL output into domain ``Finding`` objects.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from kingsec.application import ScannerPort
from kingsec.domain import Finding, Target
from kingsec.infrastructure.logging import get_logger

from .errors import ScannerExecutionError
from .ffuf_parser import parse_ffuf_json
from .runner import CommandRunner, SubprocessCommandRunner

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import FfufSettings

_logger = get_logger("kingsec.infrastructure.scanner")


class FfufScannerAdapter(ScannerPort):
    """Runs ffuf against a target and returns domain findings."""

    def __init__(
        self,
        settings: "FfufSettings",
        runner: CommandRunner | None = None,
    ) -> None:
        self._settings = settings
        self._runner: CommandRunner = runner or SubprocessCommandRunner()

    def scan(self, target: Target) -> Sequence[Finding]:
        """Scan ``target`` with ffuf and return the findings discovered."""
        args = self._build_args(target)

        _logger.info(
            "ffuf scan started",
            target=target.value,
            binary=self._settings.binary_path,
        )
        result = self._runner.run(args, timeout=self._settings.timeout_seconds)

        if result.returncode != 0:
            raise ScannerExecutionError(
                f"ffuf exited with code {result.returncode}",
                context={
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip()[:500],
                    "target": target.value,
                },
            )

        findings = parse_ffuf_json(result.stdout)
        _logger.info(
            "ffuf scan completed",
            target=target.value,
            findings=len(findings),
            duration_seconds=round(result.duration_seconds, 3),
        )
        return findings

    def _build_args(self, target: Target) -> list[str]:
        """Assemble the ffuf argument vector.

        ffuf uses ``-u <target>/FUZZ`` for the URL and ``-w <wordlist>``
        for the wordlist. Always outputs JSONL with ``-json``.
        """
        settings = self._settings
        # Normalize target: strip trailing slash for clean URL construction
        base_url = target.value.rstrip("/")
        args: list[str] = [
            settings.binary_path,
            *settings.scan_args,
            "-u",
            f"{base_url}/FUZZ",
            "-w",
            settings.wordlist,
            "-json",
        ]
        return args
