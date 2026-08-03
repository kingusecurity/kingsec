"""Shared fixtures/helpers for the integration test suite."""

from __future__ import annotations

import pytest


def _weasyprint_available() -> bool:
    """Return True only if WeasyPrint can actually render PDFs."""
    try:
        from weasyprint import HTML

        HTML(string="<p>test</p>").write_pdf()
        return True
    except Exception:
        return False


needs_weasyprint = pytest.mark.skipif(
    not _weasyprint_available(),
    reason="WeasyPrint native dependencies (GTK/Pango) are not available",
)
