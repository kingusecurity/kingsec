"""The ffuf implementation of the application ``ScannerPort``.

Composes a safe argument list from configuration, runs it through a
``CommandRunner``, translates failures into ``ScannerError``, and parses the
JSONL output into domain ``Finding`` objects.
"""

from __future__ import annotations

import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING

from kingsec.application import ScannerPort
from kingsec.domain import Finding, Target
from kingsec.infrastructure.logging import get_logger

from .errors import (
    NONZERO_EXIT_USER_MESSAGE,
    WILDCARD_RESPONSE_USER_MESSAGE,
    WORDLIST_MISSING_USER_MESSAGE,
    ScannerExecutionError,
)
from .ffuf_parser import parse_ffuf_json
from .runner import CommandRunner, SubprocessCommandRunner

if TYPE_CHECKING:
    from kingsec.infrastructure.config.models import FfufSettings

_logger = get_logger("kingsec.infrastructure.scanner")


def resolve_rate_limit_description(settings: FfufSettings) -> str:
    """What rate limiting actually applies to this scan, in ffuf's own
    terms (Phase 2B-c Priority 3) - mirrors nmap's own
    resolve_port_specification() precedent (nmap.py): the Limitations
    section must state a real recorded fact, never guess or hardcode.
    """
    if "-rate" in settings.scan_args:
        return "operator-configured via scan_args (-rate)"
    if settings.rate_limit_per_second <= 0:
        return "disabled (rate_limit_per_second=0)"
    return f"{settings.rate_limit_per_second} requests/second (ffuf -rate)"

# Wildcard-probe HTTP timeout: short and fixed, independent of the real
# scan's own configured timeout - this is one lightweight GET, not a fuzz
# pass, and must fail fast if the target is unreachable rather than eating
# into the scan's real timeout budget.
_WILDCARD_PROBE_TIMEOUT_SECONDS = 10.0


def _default_wildcard_probe(url: str, timeout: float) -> bool:
    """Request ``url`` (a random, guaranteed-nonexistent path) and report
    whether the response LOOKS like a real 404.

    Returns ``True`` if the target appears to be a catch-all/wildcard
    responder (any status other than 404 for a path that cannot exist),
    ``False`` if it correctly 404s, or if the target could not be reached
    at all (a genuine connectivity problem is not a wildcard condition -
    the real ffuf invocation will surface that error properly on its own).
    """
    try:
        req = urllib.request.Request(url, method="GET")  # nosec B310 - target is operator-authorized
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            return int(resp.status) != 404
    except urllib.error.HTTPError as exc:
        return exc.code != 404
    except (urllib.error.URLError, ValueError, TimeoutError, OSError):
        # ValueError covers a malformed/schemeless URL (e.g. a bare
        # hostname or IP without http(s)://) - not a wildcard condition
        # either; the real ffuf invocation surfaces that error properly.
        return False


class FfufScannerAdapter(ScannerPort):
    """Runs ffuf against a target and returns domain findings."""

    def __init__(
        self,
        settings: FfufSettings,
        runner: CommandRunner | None = None,
        *,
        wildcard_probe: Callable[[str, float], bool] = _default_wildcard_probe,
    ) -> None:
        self._settings = settings
        self._runner: CommandRunner = runner or SubprocessCommandRunner()
        # Injectable seam for tests (Phase 2B-c Priority 1a) - the real
        # implementation makes a genuine HTTP request, which tests should
        # never depend on a live server for. Defaults to the real check.
        self._wildcard_probe = wildcard_probe

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        """This adapter only ever runs ffuf - no target-type filtering here."""
        return {"ffuf": "FFUF"}

    def scan(self, target: Target, scanner_ids: Sequence[str] | None = None) -> Sequence[Finding]:
        """Scan ``target`` with ffuf and return the findings discovered."""
        if scanner_ids is not None and "ffuf" not in scanner_ids:
            return ()
        self._validate_config()
        self._check_for_wildcard_response(target)
        args = self._build_args(target)

        _logger.info(
            "ffuf scan started",
            target=target.value,
            binary=self._settings.binary_path,
        )
        result = self._runner.run(args, timeout=self._settings.timeout_seconds)

        findings = parse_ffuf_json(result.stdout)

        if result.returncode != 0 and not findings:
            raise ScannerExecutionError(
                f"ffuf exited with code {result.returncode}",
                context={
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip()[:500],
                    "target": target.value,
                },
                user_message=NONZERO_EXIT_USER_MESSAGE,
            )
        _logger.info(
            "ffuf scan completed",
            target=target.value,
            findings=len(findings),
            duration_seconds=round(result.duration_seconds, 3),
        )
        return findings

    def _check_for_wildcard_response(self, target: Target) -> None:
        """Abort before fuzzing if the target is a catch-all/wildcard responder.

        Phase 2B-c Priority 1a: verified directly against a real target
        (Juice Shop, a single-page app) that a random, guaranteed-
        nonexistent path returns HTTP 200 - the SPA's router serves the
        same page for any path. Fuzzing such a target with a wordlist
        turns every single word into a "finding", 4000+ of them in one
        real run (docs/E2E-EVIDENCE-PHASE2B.md Defect 3), several dozen
        scored High purely from the path's name (`.env`, `.git/HEAD`)
        despite the response being the identical generic SPA shell every
        time. gobuster already refuses to proceed on this exact condition
        with a specific, actionable message - this matches that standard
        rather than flooding.
        """
        probe_path = f"{target.value.rstrip('/')}/{uuid.uuid4().hex}"
        if self._wildcard_probe(probe_path, _WILDCARD_PROBE_TIMEOUT_SECONDS):
            raise ScannerExecutionError(
                "ffuf aborted: target returns a non-404 response for a "
                "nonexistent path (wildcard/catch-all response)",
                context={"target": target.value, "probe_path": probe_path},
                user_message=WILDCARD_RESPONSE_USER_MESSAGE,
            )

    def _validate_config(self) -> None:
        """Fail fast if required configuration is missing."""
        if not self._settings.wordlist.strip():
            raise ScannerExecutionError(
                "ffuf wordlist is not configured",
                context={"binary": self._settings.binary_path},
                user_message=WORDLIST_MISSING_USER_MESSAGE,
            )

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
        # Phase 2B-c Priority 3: a conservative default rate limit unless
        # the operator already configured one (or explicitly disabled it
        # with rate_limit_per_second=0) via scan_args.
        if settings.rate_limit_per_second > 0 and "-rate" not in settings.scan_args:
            args.extend(["-rate", str(settings.rate_limit_per_second)])
        return args
