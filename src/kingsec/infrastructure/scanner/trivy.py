"""The Trivy implementation of the application ``ScannerPort``.

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
from .trivy_parser import parse_trivy_json

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import TrivySettings

_logger = get_logger("kingsec.infrastructure.scanner")


class TrivyScannerAdapter(ScannerPort):
    """Runs Trivy against a target and returns domain findings."""

    def __init__(
        self,
        settings: TrivySettings,
        runner: CommandRunner | None = None,
    ) -> None:
        self._settings = settings
        self._runner: CommandRunner = runner or SubprocessCommandRunner()

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        """This adapter only ever runs Trivy - no target-type filtering here."""
        return {"trivy": "Trivy"}

    def scan(self, target: Target, scanner_ids: Sequence[str] | None = None) -> Sequence[Finding]:
        """Scan ``target`` with Trivy and return the findings discovered."""
        if scanner_ids is not None and "trivy" not in scanner_ids:
            return ()
        args = self._build_args(target)

        _logger.info(
            "trivy scan started",
            target=target.value,
            binary=self._settings.binary_path,
            scan_type=self._scan_type(target),
        )
        result = self._runner.run(args, timeout=self._settings.timeout_seconds)

        # A non-zero process that produced nothing is an execution failure.
        # On exit zero, however, Trivy must emit a valid JSON report even for
        # a clean scan, so the parser rejects blank stdout honestly.
        findings: list[Finding]
        if result.returncode != 0 and not result.stdout.strip():
            findings = []
        else:
            findings = parse_trivy_json(result.stdout)

        if result.returncode != 0 and not findings:
            raise ScannerExecutionError(
                f"trivy exited with code {result.returncode}",
                context={
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip()[:500],
                    "target": target.value,
                },
                user_message=NONZERO_EXIT_USER_MESSAGE,
            )
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
        if target.type is TargetType.SOURCE_PATH:
            self._validate_source_path(target)
        args: list[str] = [
            settings.binary_path,
            self._scan_type(target),
            *settings.scan_args,
            "--format",
            "json",
            "--",
            target.value,
        ]
        return args

    @staticmethod
    def _scan_type(target: Target) -> str:
        if target.type is TargetType.SOURCE_PATH:
            return "fs"
        if target.type is TargetType.CONTAINER_IMAGE:
            return "image"
        raise ScannerExecutionError(
            f"trivy requires source_path or container_image, got {target.type.value!r}",
            context={"target_type": target.type.value},
            user_message=(
                "Trivy requires either an absolute source path visible to the KingSec server "
                "or a container image reference."
            ),
        )

    @staticmethod
    def _validate_source_path(target: Target) -> None:
        """Fail before execution when Trivy cannot inspect the local target."""
        path = Path(target.value)
        if not path.exists():
            raise ScannerExecutionError(
                f"trivy source path does not exist: {target.value!r}",
                context={"target_type": target.type.value, "check_failed": "source path does not exist"},
                user_message=(
                    "Trivy could not access the source path. Verify that it exists and is readable "
                    "by the KingSec service account."
                ),
            )
        if not path.is_file() and not path.is_dir():
            raise ScannerExecutionError(
                f"trivy source path is not a file or directory: {target.value!r}",
                context={"target_type": target.type.value, "check_failed": "source path is not scannable"},
                user_message=(
                    "Trivy could not access the source path. Verify that it names a readable file "
                    "or directory available to the KingSec service account."
                ),
            )
        access_mode = os.R_OK | (os.X_OK if path.is_dir() else 0)
        if not os.access(path, access_mode):
            raise ScannerExecutionError(
                f"trivy source path is not readable: {target.value!r}",
                context={"target_type": target.type.value, "check_failed": "source path is not readable"},
                user_message=(
                    "Trivy could not access the source path. Verify that it exists and is readable "
                    "by the KingSec service account."
                ),
            )
