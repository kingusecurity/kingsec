"""Errors for the reporting adapter.

``ReportGenerationError`` is the single failure type the application sees for
report rendering. It subclasses the shared kernel's ``KingSecError`` with its own
stable code (KS-REPORT-001), so it flows through the existing exception handling
while keeping every rendering-library exception contained inside infrastructure.
"""

from __future__ import annotations

from kingsec.shared.errors import KingSecError


class ReportGenerationError(KingSecError):
    """A report (HTML or PDF) could not be rendered."""

    code = "KS-REPORT-001"
    default_user_message = "The report could not be generated."
