"""Dependency-injection wiring for reporting.

``register_reporting`` binds the report generator to the ``ReportGeneratorPort``
on the Module 2.4 container. The container is duck-typed (needs only
``register_instance``), so infrastructure never imports the bootstrap layer.
"""

from __future__ import annotations

from kingsec.application import ReportGeneratorPort
from kingsec.infrastructure.logging import get_logger

from .adapter import ReportGeneratorAdapter

_logger = get_logger("kingsec.infrastructure.reporting")


def register_reporting(
    container: object,
    *,
    output_format: str = "pdf",
    brand_name: str = "KingSec",
) -> ReportGeneratorPort:
    """Register the report generator adapter as ``ReportGeneratorPort``.

    Args:
        container: The bootstrap DI container (duck-typed: needs
            ``register_instance``). The Module 2.4 ``Container`` satisfies this.
        output_format: ``"pdf"`` (default) or ``"html"``.
        brand_name: Company branding placeholder for the report.

    Returns:
        The registered ``ReportGeneratorPort`` implementation.
    """

    adapter = ReportGeneratorAdapter(output_format=output_format, brand_name=brand_name)
    register = getattr(container, "register_instance")
    register(ReportGeneratorPort, adapter)
    _logger.info("reporting registered", format=output_format)
    return adapter
