"""The Semgrep implementation of the application ``ScannerPort``.

Composes a safe argument list from configuration, runs it through a
``CommandRunner``, translates failures into ``ScannerError``, and parses the
JSON output into domain ``Finding`` objects.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from kingsec.application import ScannerPort
from kingsec.domain import Finding, Target, TargetType
from kingsec.infrastructure.logging import get_logger

from .errors import NONZERO_EXIT_USER_MESSAGE, ScannerExecutionError
from .runner import CommandRunner, SubprocessCommandRunner
from .semgrep_parser import parse_semgrep_json

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import SemgrepSettings

_logger = get_logger("kingsec.infrastructure.scanner")


class SemgrepScannerAdapter(ScannerPort):
    """Runs Semgrep against a target and returns domain findings."""

    def __init__(
        self,
        settings: SemgrepSettings,
        runner: CommandRunner | None = None,
    ) -> None:
        self._settings = settings
        self._runner: CommandRunner = runner or SubprocessCommandRunner()

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        """This adapter only ever runs Semgrep - no target-type filtering here."""
        return {"semgrep": "Semgrep"}

    def scan(self, target: Target, scanner_ids: Sequence[str] | None = None) -> Sequence[Finding]:
        """Scan ``target`` with Semgrep and return the findings discovered."""
        if scanner_ids is not None and "semgrep" not in scanner_ids:
            return ()
        args = self._build_args(target)

        _logger.info(
            "semgrep scan started",
            target=target.value,
            binary=self._settings.binary_path,
        )
        result = self._runner.run(args, timeout=self._settings.timeout_seconds)

        # A non-zero process that produced nothing is an execution failure.
        # On exit zero, however, Semgrep must emit a valid JSON report even
        # for a clean scan, so the parser rejects blank stdout honestly.
        findings: list[Finding]
        if result.returncode != 0 and not result.stdout.strip():
            findings = []
        else:
            findings = parse_semgrep_json(result.stdout)

        if result.returncode != 0 and not findings:
            raise ScannerExecutionError(
                f"semgrep exited with code {result.returncode}",
                context={
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip()[:500],
                    "target": target.value,
                },
                user_message=NONZERO_EXIT_USER_MESSAGE,
            )
        _logger.info(
            "semgrep scan completed",
            target=target.value,
            findings=len(findings),
            duration_seconds=round(result.duration_seconds, 3),
        )
        return findings

    def _build_args(self, target: Target) -> list[str]:
        """Assemble the Semgrep argument vector.

        Semgrep uses ``semgrep scan --json [--config <rules>] <target>``.
        """
        if target.type is not TargetType.SOURCE_PATH:
            raise ScannerExecutionError(
                f"semgrep requires a source_path target, got {target.type.value!r}",
                context={"target_type": target.type.value},
                user_message="Semgrep requires an absolute source path visible to the KingSec server.",
            )
        self._validate_source_path(target)
        settings = self._settings
        args: list[str] = [
            settings.binary_path,
            "scan",
            *settings.scan_args,
            "--json",
        ]
        if settings.rules:
            args.extend(["--config", settings.rules])
        args.extend(["--", target.value])
        return args

    @staticmethod
    def _validate_source_path(target: Target) -> None:
        """Fail before execution when Semgrep cannot inspect the local target."""
        path = Path(target.value)
        if not path.exists():
            raise ScannerExecutionError(
                f"semgrep source path does not exist: {target.value!r}",
                context={"target_type": target.type.value, "check_failed": "source path does not exist"},
                user_message=(
                    "Semgrep could not access the source path. Verify that it exists and is readable "
                    "by the KingSec service account."
                ),
            )
        if not path.is_file() and not path.is_dir():
            raise ScannerExecutionError(
                f"semgrep source path is not a file or directory: {target.value!r}",
                context={"target_type": target.type.value, "check_failed": "source path is not scannable"},
                user_message=(
                    "Semgrep could not access the source path. Verify that it names a readable file "
                    "or directory available to the KingSec service account."
                ),
            )
        access_mode = os.R_OK | (os.X_OK if path.is_dir() else 0)
        if not os.access(path, access_mode):
            raise ScannerExecutionError(
                f"semgrep source path is not readable: {target.value!r}",
                context={"target_type": target.type.value, "check_failed": "source path is not readable"},
                user_message=(
                    "Semgrep could not access the source path. Verify that it exists and is readable "
                    "by the KingSec service account."
                ),
            )
