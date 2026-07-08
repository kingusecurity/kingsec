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
