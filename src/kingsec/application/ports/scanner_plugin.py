"""Outbound port: scanner plugin contract.

Every scanner (Nuclei, Nmap, Nikto, ffuf, etc.) implements this interface.
The application layer depends only on this abstraction — it never knows which
concrete scanner is running.

A plugin is self-describing: it declares its metadata, capabilities, and
availability. The orchestrator (an infrastructure concern) uses these declarations
to decide which plugins to invoke for a given target.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain import (
    PluginAvailability,
    PluginConfig,
    ScannerCapability,
    ScannerPluginMetadata,
    ScannerResult,
    Target,
)


class ScannerPluginPort(ABC):
    """The contract every scanner plugin implements."""

    @abstractmethod
    def metadata(self) -> ScannerPluginMetadata:
        """Return this plugin's identity card.

        Called once during registration. The returned metadata is immutable
        and used for display, versioning, and capability negotiation.
        """
        ...

    @abstractmethod
    def capabilities(self) -> tuple[ScannerCapability, ...]:
        """Declare what this plugin can scan and how.

        The orchestrator uses capabilities to decide which plugins to invoke
        for a given target type. A plugin that can handle multiple target
        types or scan categories returns multiple capabilities.
        """
        ...

    @abstractmethod
    def is_available(self) -> PluginAvailability:
        """Check if the scanner binary or API is reachable right now.

        Called during registration and before each scan. Returns a value
        object indicating whether the plugin is ready to execute.
        """
        ...

    @abstractmethod
    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        """Execute the scan and return normalized results.

        The plugin is responsible for:
        1. Building the correct argument list or API request
        2. Invoking the scanner (subprocess, HTTP, etc.)
        3. Parsing the output into domain Finding objects
        4. Returning a ScannerResult with findings, timing, and warnings

        The orchestrator handles timeout enforcement and error isolation.
        """
        ...

    def health_check(self) -> None:
        """Pre-flight check before scanning.

        Default: re-checks availability and raises if unavailable.
        Override for scanners that need deeper validation (e.g. template
        directory exists, API key is valid, port is open).
        """
        availability = self.is_available()
        if not availability.available:
            from ..errors import ScannerUnavailableError

            raise ScannerUnavailableError(
                availability.reason or "scanner is not available",
                scanner_id=self.metadata().id.value,
            )

    def shutdown(self) -> None:
        """Clean up resources held by this plugin.

        Default: no-op. Override for plugins that hold open connections,
        subprocess handles, or file handles that need explicit teardown.
        Called in LIFO order during application shutdown.
        """
