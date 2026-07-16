"""Dependency-injection wiring for the scanner.

``register_scanner`` creates scanner plugins (Nuclei, Nmap, Nikto, ffuf,
Gobuster), registers them in the plugin registry, builds the
``ScannerOrchestrator``, and binds it to ``ScannerPort`` on the container.
It takes the container as a duck-typed object (needs only
``register_instance``) so infrastructure never imports the bootstrap layer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from kingsec.application import ScannerPort
from kingsec.infrastructure.logging import get_logger

from .orchestrator import ScannerOrchestrator
from .plugins.ffuf import FfufPlugin
from .plugins.gobuster import GobusterPlugin
from .plugins.nikto import NiktoPlugin
from .plugins.nmap import NmapPlugin
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
    """Register scanner plugins and bind the orchestrator to ``ScannerPort``.

    Creates and registers Nuclei, Nmap, Nikto, ffuf, and Gobuster plugins.
    Unavailable plugins (missing binary) are registered but will raise on
    scan — the orchestrator handles this gracefully.
    """
    registry = InMemoryPluginRegistry()

    # Nuclei plugin
    nuclei_plugin = NucleiPlugin(settings.scanner, runner=runner)
    registry.register(nuclei_plugin)

    # Nmap plugin
    nmap_plugin = NmapPlugin(settings.nmap, runner=runner)
    registry.register(nmap_plugin)

    # Nikto plugin
    nikto_plugin = NiktoPlugin(settings.nikto, runner=runner)
    registry.register(nikto_plugin)

    # ffuf plugin
    ffuf_plugin = FfufPlugin(settings.ffuf, runner=runner)
    registry.register(ffuf_plugin)

    # Gobuster plugin
    gobuster_plugin = GobusterPlugin(settings.gobuster, runner=runner)
    registry.register(gobuster_plugin)

    orchestrator = ScannerOrchestrator(registry)
    register = getattr(container, "register_instance")
    register(ScannerPort, orchestrator)
    _logger.info("scanner registered", engines="nuclei,nmap,nikto,ffuf,gobuster")
    return orchestrator
