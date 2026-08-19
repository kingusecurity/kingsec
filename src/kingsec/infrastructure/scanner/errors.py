"""Errors for the scanner adapter.

The scanner reuses the shared kernel's :class:`ScannerError` (code KS-SCAN-001)
as the single failure type the application sees. We subclass it here only to give
each failure mode a clear name in tracebacks while keeping the stable code and
safe user message. Infrastructure is allowed to depend on the shared kernel, so
this keeps subprocess/parsing details out of the application layer entirely.
"""

from __future__ import annotations

from kingsec.shared.errors import ScannerError


class ScannerExecutionError(ScannerError):
    """The scanner process failed to run, timed out, or exited with an error."""


class ScannerOutputError(ScannerError):
    """The scanner ran but produced output that could not be parsed."""


# Shared by runner.py's SubprocessCommandRunner (FileNotFoundError at actual
# execution time) AND all 9 plugins' is_available()/health_check() default
# implementation (ScannerPluginPort.health_check(), application/ports/
# scanner_plugin.py - a pre-flight shutil.which() check). Both are the SAME
# failure mode (Phase 08 §3.1) reached via two different code paths - in
# practice health_check() fires first for a genuinely-missing binary, so
# runner.py's own translation is the rarer, race-condition-only path (binary
# present at health-check time, removed before the subprocess actually
# runs). Discovered mid-phase: the health_check() path was not in the
# original inventory and was found leaking the raw configured path via
# ScannerUnavailableError (a ScannerPluginError/ApplicationError, so
# Phase 07's safe_failure_message() treated it as already-safe and never
# touched it) - see the Phase 08 report §2/§4 for the full account.
BINARY_ABSENT_USER_MESSAGE = (
    "The scanner binary could not be found. Check that this scanner is "
    "installed in the deployment environment."
)

# Shared across all 9 adapters' identical non-zero-exit guard clause
# (Phase 08 §3.1/§4: same failure mode, same message everywhere it's
# raised - a single constant makes divergence structurally impossible,
# rather than relying on 9 separately-maintained literals staying in sync).
NONZERO_EXIT_USER_MESSAGE = (
    "The scan process exited with an error before producing usable results. "
    "Check the scanner's configuration or try again."
)

# Shared by ffuf and gobuster - both fail-fast on the same missing-wordlist
# precondition (Phase 08 §3.1: same failure mode, two adapters).
WORDLIST_MISSING_USER_MESSAGE = (
    "The scanner's configured wordlist could not be found. "
    "Check the scanner's configuration in the deployment environment."
)
