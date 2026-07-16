"""Dependency-injection wiring for the scanner.

``register_scanner`` creates the Nuclei plugin, registers it in the plugin
registry, builds the ``ScannerOrchestrator``, and binds it to ``ScannerPort``
on the container. It takes the container as a duck-typed object (needs only
``register_instance``) so infrastructure never imports the bootstrap layer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from kingsec.application import ScannerPort
from kingsec.infrastructure.logging import get_logger

from .orchestrator import ScannerOrchestrator
from .plugins.nuclei import NucleiPlugin
from .registry import InMemoryPluginRegistry
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
    """Register the Nuclei plugin and bind the orchestrator to ``ScannerPort``.

    Args:
        container: The bootstrap DI container (duck-typed: needs
            ``register_instance``). The Module 2.4 ``Container`` satisfies this.
        settings: Application settings (uses ``settings.scanner``).
        runner: Optional command runner override (mainly for tests).

    Returns:
        The registered ``ScannerPort`` implementation (the orchestrator).
    """
    registry = InMemoryPluginRegistry()
    plugin = NucleiPlugin(settings.scanner, runner=runner)
    registry.register(plugin)

    orchestrator = ScannerOrchestrator(registry)
    register = getattr(container, "register_instance")
    register(ScannerPort, orchestrator)
    _logger.info("scanner registered", engine="nuclei")
    return orchestrator
