"""The Nikto implementation of the application ``ScannerPort``.

Composes a safe argument list from configuration, runs it through a
``CommandRunner``, translates failures into ``ScannerError``, and parses the
text output into domain ``Finding`` objects.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from kingsec.application import ScannerPort
from kingsec.domain import Finding, Target
from kingsec.infrastructure.logging import get_logger

from .errors import NONZERO_EXIT_USER_MESSAGE, ScannerExecutionError
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

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        """This adapter only ever runs Nikto - no target-type filtering here."""
        return {"nikto": "Nikto"}

    def scan(self, target: Target, scanner_ids: Sequence[str] | None = None) -> Sequence[Finding]:
        """Scan ``target`` with Nikto and return the findings discovered."""
        if scanner_ids is not None and "nikto" not in scanner_ids:
            return ()
        args = self._build_args(target)

        _logger.info(
            "nikto scan started",
            target=target.value,
            binary=self._settings.binary_path,
        )
        result = self._runner.run(args, timeout=self._settings.timeout_seconds)

        findings = parse_nikto_output(result.stdout)

        if result.returncode != 0 and not findings:
            raise ScannerExecutionError(
                f"nikto exited with code {result.returncode}",
                context={
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip()[:500],
                    "target": target.value,
                },
                user_message=NONZERO_EXIT_USER_MESSAGE,
            )
        _logger.info(
            "nikto scan completed",
            target=target.value,
            findings=len(findings),
            duration_seconds=round(result.duration_seconds, 3),
        )
        return findings

    @staticmethod
    def _parse_target(target: Target) -> tuple[str, int | None, bool]:
        """Extract (hostname, port, use_ssl) from a target value.

        Handles URLs (``https://host:443/path``) and bare host:port strings.
        """
        raw = target.value.strip()
        host: str = raw
        port: int | None = None
        use_ssl: bool = False

        if "://" in raw:
            parsed = urlparse(raw)
            host = parsed.hostname or raw
            port = parsed.port
            use_ssl = parsed.scheme == "https"
        elif ":" in raw:
            parts = raw.rsplit(":", 1)
            if parts[1].isdigit():
                host = parts[0]
                port = int(parts[1])

        return host, port, use_ssl

    def _build_args(self, target: Target) -> list[str]:
        """Assemble the Nikto argument vector.

        Extracts hostname, optional port, and SSL flag from the target.
        """
        settings = self._settings
        host, port, use_ssl = self._parse_target(target)
        args: list[str] = [
            settings.binary_path,
            *settings.scan_args,
            "-h",
            host,
        ]
        if use_ssl and "-ssl" not in args:
            args.append("-ssl")
        if port is not None:
            args.extend(["-p", str(port)])
        return args
