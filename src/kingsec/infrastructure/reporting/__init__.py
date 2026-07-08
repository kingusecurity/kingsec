"""KingSec report generation adapter (infrastructure layer).

Implements the application's ``ReportGeneratorPort`` by rendering a domain
``Report`` snapshot into a professional HTML document and/or a PDF derived from
it. The PDF rendering library is isolated behind ``renderer.py``; the domain and
application never import any reporting library.

Public API
    Adapter:   ReportGeneratorAdapter
    Renderer:  ReportRenderer
    Templates: render_report_html
    Errors:    ReportGenerationError
    DI wiring: register_reporting
"""

from __future__ import annotations

from .adapter import ReportGeneratorAdapter
from .errors import ReportGenerationError
from .provisioning import register_reporting
from .renderer import ReportRenderer
from .templates import render_report_html

__all__ = [
    "ReportGenerationError",
    "ReportGeneratorAdapter",
    "ReportRenderer",
    "register_reporting",
    "render_report_html",
]
