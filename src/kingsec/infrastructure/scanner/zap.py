"""The OWASP ZAP implementation of the application ``ScannerPort``.

Composes a safe argument list from configuration, runs it through a
``CommandRunner``, translates failures into ``ScannerError``, and parses the
JSON output into domain ``Finding`` objects.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from pathlib import Path
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
        *,
        data_dir: Path | None = None,
    ) -> None:
        self._settings = settings
        self._runner: CommandRunner = runner or SubprocessCommandRunner()
        # KingSec's own configured data directory (Settings.storage.data_dir),
        # NOT ZAP's install directory - see _build_args()'s -quickout path.
        # Defaults to the same ~/.kingsec convention used elsewhere
        # (_default_wordlist_path()) for direct construction/tests that
        # don't thread the real setting through.
        self._data_dir = data_dir or (Path.home() / ".kingsec")

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

        # KNOWN, UNRESOLVED GAP (verified empirically against the real
        # binary, Task 5 hang investigation): ZAP writes -quickurl/-quickout
        # results to the FILE named by -quickout, never to stdout - stdout
        # only carries a "Writing results to <path>" line and progress/log
        # text. parse_zap_json(result.stdout) below is very likely parsing
        # the wrong stream and returning no findings from any real ZAP
        # invocation, regardless of the -quickout path fix above. Left
        # exactly as-is: reading the output file instead is bound up with
        # the still-undecided ZAP invocation redesign (see the Task 5 hang
        # investigation report) and must not be changed ahead of that
        # decision.
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

        ZAP quick scan: ``zap -quickurl <target> -quickout <data_dir>/...json``

        Task 5 output-path fix: the ``-quickout`` filename is a REAL,
        absolute path under KingSec's own configured data directory,
        never a bare relative string like the previous ``"json"`` literal
        - that resolved relative to the process's own working directory,
        which for a real scanner binary can easily be its OWN install
        directory (verified against the real Windows ZAP installer
        default, ``C:\\Program Files\\...``, not writable by the account
        running KingSec). KingSec must never write into a scanner's
        install directory. Each invocation gets a unique filename (a UUID
        suffix) so concurrent scans cannot clobber each other's output
        file.
        """
        settings = self._settings
        output_dir = self._data_dir / "scanner-output"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"zap-quickscan-{uuid.uuid4().hex}.json"
        args: list[str] = [
            settings.binary_path,
            *settings.scan_args,
            "-quickurl",
            target.value,
            "-quickout",
            str(output_path),
        ]
        return args
