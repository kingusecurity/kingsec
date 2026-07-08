"""Dependency-injection wiring for the scanner.

``register_scanner`` binds the Nuclei adapter to the ``ScannerPort`` on the
Module 2.4 container. It takes the container as a duck-typed object (needs only
``register_instance``) so infrastructure never imports the bootstrap layer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from kingsec.application import ScannerPort
from kingsec.infrastructure.logging import get_logger

from .nuclei import NucleiScannerAdapter
from .runner import CommandRunner

if TYPE_CHECKING:  # typing only
    from kingsec.infrastructure.config import Settings

_logger = get_logger("kingsec.infrastructure.scanner")


def register_scanner(
    container: object,
    settings: "Settings",
    *,
    runner: CommandRunner | None = None,
) -> ScannerPort:
    """Register the Nuclei scanner adapter on the container as ``ScannerPort``.

    Args:
        container: The bootstrap DI container (duck-typed: needs
            ``register_instance``). The Module 2.4 ``Container`` satisfies this.
        settings: Application settings (uses ``settings.scanner``).
        runner: Optional command runner override (mainly for tests).

    Returns:
        The registered ``ScannerPort`` implementation.
    """

    adapter = NucleiScannerAdapter(settings.scanner, runner=runner)
    register = getattr(container, "register_instance")
    register(ScannerPort, adapter)
    _logger.info("scanner registered", engine="nuclei")
    return adapter
