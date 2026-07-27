"""The Nuclei implementation of the application ``ScannerPort``.

Composes the safe argument list from configuration, runs it through a
``CommandRunner``, translates any failure into a ``ScannerError``, and parses the
JSONL output into domain ``Finding`` objects. This is the class the composition
root binds to ``ScannerPort``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from kingsec.application import ScannerPort
from kingsec.domain import Finding, Target
from kingsec.infrastructure.logging import get_logger

from .errors import ScannerExecutionError
from .parser import parse_nuclei_jsonl
from .runner import CommandRunner, SubprocessCommandRunner

if TYPE_CHECKING:  # typing only; avoids importing config internals at runtime
    from kingsec.infrastructure.config.models import ScannerSettings

_logger = get_logger("kingsec.infrastructure.scanner")


class NucleiScannerAdapter(ScannerPort):
    """Runs Nuclei against a target and returns domain findings."""

    def __init__(
        self,
        settings: ScannerSettings,
        runner: CommandRunner | None = None,
    ) -> None:
        """Initialise the adapter.

        Args:
            settings: The scanner configuration (binary path, templates dir,
                timeout, rate limit).
            runner: The command runner to execute Nuclei with. Defaults to the
                real subprocess runner; tests inject a fake.
        """
        self._settings = settings
        self._runner: CommandRunner = runner or SubprocessCommandRunner()

    def scan(self, target: Target) -> Sequence[Finding]:
        """Scan ``target`` with Nuclei and return the findings discovered.

        Args:
            target: The validated domain target to scan. It is passed to Nuclei
                as a single ``argv`` element, so it cannot inject arguments.

        Returns:
            The findings discovered (possibly empty).

        Raises:
            ScannerError: If the scanner is misconfigured, fails to run, times
                out, or exits with a non-zero status.
        """
        self._validate_templates_dir()
        args = self._build_args(target)

        _logger.info(
            "scan started",
            target=target.value,
            binary=self._settings.binary_path,
        )
        result = self._runner.run(args, timeout=self._settings.timeout_seconds)

        findings = parse_nuclei_jsonl(result.stdout)

        if result.returncode != 0 and not findings:
            raise ScannerExecutionError(
                f"nuclei exited with code {result.returncode}",
                context={
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip()[:500],
                    "target": target.value,
                },
            )
        _logger.info(
            "scan completed",
            target=target.value,
            findings=len(findings),
            duration_seconds=round(result.duration_seconds, 3),
        )
        return findings

    def _build_args(self, target: Target) -> list[str]:
        """Assemble the Nuclei argument vector (list form — never a shell string).

        Flags chosen for safe, deterministic, non-interactive runs:
            -jsonl  structured output   -silent  suppress banner/noise
            -nc     no ANSI colour       -duc     no auto update-check (no surprise
                                                  network calls mid-scan)
            -rl     rate limit (safety)  -t       templates dir (if configured)
        """
        settings = self._settings
        args: list[str] = [
            settings.binary_path,
            "-u",
            target.value,
            "-jsonl",
            "-silent",
            "-nc",
            "-duc",
            "-rl",
            str(settings.rate_limit),
        ]
        if settings.templates_dir is not None:
            args += ["-t", str(settings.templates_dir)]
        return args

    def _validate_templates_dir(self) -> None:
        """Fail fast with a clear error if a configured templates dir is missing."""
        templates_dir = self._settings.templates_dir
        if templates_dir is not None and not templates_dir.is_dir():
            raise ScannerExecutionError(
                f"configured templates directory does not exist: {templates_dir}",
                context={"templates_dir": str(templates_dir)},
            )
