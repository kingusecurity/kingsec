"""Nuclei scanner plugin.

Wraps the existing ``NucleiScannerAdapter`` as a ``ScannerPluginPort``,
delegating all subprocess execution and parsing to the already-tested
implementation. Zero behavioral change.
"""

from __future__ import annotations

from .adapter import NucleiPlugin

__all__ = ["NucleiPlugin"]
