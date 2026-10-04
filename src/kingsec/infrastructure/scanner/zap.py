"""The OWASP ZAP implementation of the application ``ScannerPort``.

Composes a safe argument list from configuration, runs it through a
``CommandRunner``, translates failures into ``ScannerError``, and parses the
JSON output into domain ``Finding`` objects.
"""

from __future__ import annotations

import json
import ntpath
import os.path
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from kingsec.application import ScannerPort
from kingsec.application.scanner_discovery import find_executable
from kingsec.domain import Finding, Target
from kingsec.infrastructure.logging import get_logger

from .errors import NONZERO_EXIT_USER_MESSAGE, ScannerExecutionError
from .runner import CommandResult, CommandRunner, SubprocessCommandRunner
from .zap_parser import parse_zap_json

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import ZapSettings

_logger = get_logger("kingsec.infrastructure.scanner")

# Task 5B Priority 3: a code-level default the adapter itself always
# prepends - not something an operator can omit or strip via
# ZapSettings.scan_args, since scan_args only ever ADDS elements to the
# argv this class builds; it never has the ability to remove one. Without
# -cmd, `-quickurl` runs inside ZAP's full desktop GUI (verified against
# the real binary - see the Task 5 hang investigation report) instead of
# exiting when the command-line options complete.
_HEADLESS_FLAG = "-cmd"


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
        args, cwd, output_path = self._build_args(target)

        _logger.info(
            "zap scan started",
            target=target.value,
            binary=args[0],
        )
        result = self._runner.run(args, timeout=self._settings.timeout_seconds, cwd=cwd)

        try:
            findings = self._read_findings(output_path, result, target)
        finally:
            # Task 5B Priority 1: the file has served its purpose (parsed
            # or definitively unusable) either way - clean it up so it
            # doesn't accumulate forever in the data directory.
            output_path.unlink(missing_ok=True)

        _logger.info(
            "zap scan completed",
            target=target.value,
            findings=len(findings),
            duration_seconds=round(result.duration_seconds, 3),
        )
        return findings

    def _read_findings(self, output_path: Path, result: CommandResult, target: Target) -> list[Finding]:
        """Read and parse ZAP's real report FILE - never ``returncode`` alone.

        Task 5B Priority 1: every ZAP scan in this product's history
        returned zero findings while reporting SUCCESS - ``parse_zap_json``
        was parsing ``result.stdout``, but ZAP writes its JSON report to
        the ``-quickout`` FILE; stdout only ever carries a "Writing
        results to <path>" line and progress/log text. Confirmed
        empirically both for the bug (stdout never contained the JSON)
        and for the fix (the file always did, once ``-cmd`` is used).

        ``returncode`` is not trustworthy either: verified empirically
        that ``-cmd`` can exit 0 while reporting a real configuration
        error ("the directory ... is not writable") with no output file
        at all. The only honest success signal is: the file exists, is
        non-empty, and is valid ZAP-shaped JSON. Any of those failing is
        a FAILED scan with a reason naming exactly which check failed -
        never a silent "succeeded with zero findings."
        """
        if not output_path.exists():
            raise ScannerExecutionError(
                f"zap did not write an output file at {output_path!r}",
                context={
                    "check_failed": "output file missing",
                    "returncode": result.returncode,
                    "stdout": result.stdout.strip()[:500],
                    "stderr": result.stderr.strip()[:500],
                    "target": target.value,
                },
                user_message=NONZERO_EXIT_USER_MESSAGE,
            )

        raw_output = output_path.read_text(encoding="utf-8")
        if not raw_output.strip():
            raise ScannerExecutionError(
                f"zap wrote an empty output file at {output_path!r}",
                context={
                    "check_failed": "output file empty",
                    "returncode": result.returncode,
                    "target": target.value,
                },
                user_message=NONZERO_EXIT_USER_MESSAGE,
            )

        try:
            parsed = json.loads(raw_output)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ScannerExecutionError(
                f"zap output file did not contain valid JSON: {output_path!r}",
                context={
                    "check_failed": "output file did not parse as JSON",
                    "returncode": result.returncode,
                    "target": target.value,
                },
                cause=exc,
                user_message=NONZERO_EXIT_USER_MESSAGE,
            ) from exc

        if not isinstance(parsed, dict) or "site" not in parsed:
            raise ScannerExecutionError(
                f"zap output file did not have the expected ZAP report shape: {output_path!r}",
                context={
                    "check_failed": "output file missing the 'site' key",
                    "returncode": result.returncode,
                    "target": target.value,
                },
                user_message=NONZERO_EXIT_USER_MESSAGE,
            )

        # parse_zap_json is deliberately lenient about the CONTENTS of an
        # already-confirmed-valid ZAP report (a genuinely clean scan is a
        # legitimate zero-finding result) - the three checks above are
        # what rule out "it never produced a real report" first.
        return parse_zap_json(raw_output)

    def _build_args(self, target: Target) -> tuple[list[str], str | None, Path]:
        """Assemble the ZAP argument vector, its working directory, and its output file.

        ZAP quick scan: ``<resolved ZAP.exe> -cmd -quickurl <target> -quickout <data_dir>/...json``

        ``settings.binary_path`` is resolved through ``find_executable()``
        — the SAME function ``kingsec doctor`` uses (one shared resolution
        function) — to an absolute path before it becomes ``argv[0]``,
        instead of being passed through as whatever string configuration
        holds. ``cwd`` is set to that binary's own directory: ``ZAP.exe``
        (an install4j-generated native launcher, not a shell script)
        resolves its own bundled classpath relative to ITS directory, not
        the caller's — invoking it with the caller's cwd silently fails
        to find its jars. If resolution fails, falls back to the
        configured string unchanged and no ``cwd`` — the runner will then
        surface the same clear "binary not found" error it always did,
        rather than this method masking a resolution failure with a
        guess.

        ``-cmd`` (Task 5B Priority 3) is always present, right after the
        binary, unconditionally — see ``_HEADLESS_FLAG``'s module-level
        docstring. Without it ``-quickurl`` opens ZAP's full desktop GUI.

        The ``-quickout`` filename is a REAL, absolute path under KingSec's
        own configured data directory, never a bare relative string. A
        bare ``"json"`` resolves relative to ``cwd`` — which is now ZAP's
        own install directory, per the fix above — and that directory is
        very often not writable by the account running KingSec (verified
        against the real installer default, ``C:\\Program Files\\...``).
        KingSec must never write into a scanner's install directory.
        Each invocation gets a unique filename (a UUID suffix) so
        concurrent scans cannot clobber each other's output file. The
        returned path is also what ``scan()`` reads the real results from
        — see ``_read_findings()``.
        """
        settings = self._settings
        resolved = find_executable(settings.binary_path)
        binary_path = resolved or settings.binary_path
        # find_executable() may return a Windows-style path (ZAP's default
        # install location, e.g. via a shared config value) even when KingSec
        # itself runs on Linux. os.path only splits on the native separator,
        # so Path(<windows path>).parent is '.' on POSIX and ZAP would start
        # in the wrong cwd, silently failing to find its jars. Detect the
        # flavor and parse accordingly.
        cwd: str | None
        if resolved and ("\\" in resolved or (len(resolved) > 1 and resolved[1] == ":")):
            cwd = ntpath.dirname(resolved)
        else:
            cwd = os.path.dirname(resolved) if resolved else None
        output_dir = self._data_dir / "scanner-output"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"zap-quickscan-{uuid.uuid4().hex}.json"
        args: list[str] = [
            binary_path,
            _HEADLESS_FLAG,
            *settings.scan_args,
            "-quickurl",
            target.value,
            "-quickout",
            str(output_path),
        ]
        return args, cwd, output_path
