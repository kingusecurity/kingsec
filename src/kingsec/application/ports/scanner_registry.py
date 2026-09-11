"""Outbound port: scanner plugin registry.

The registry is the central catalog of available scanner plugins. It owns
plugin lifecycle (registration, lookup, capability-based resolution) but
does NOT own execution — that is the executor's responsibility.

This separation keeps the registry simple (a catalog) and the executor
focused (lifecycle + error isolation).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.application.ports.scanner_plugin import ScannerPluginPort
from kingsec.domain import PluginAvailability, ScannerId, ScannerPluginMetadata, Target, TargetType


class ScannerPluginRegistry(ABC):
    """Manages the discovery and lookup of scanner plugins."""

    @abstractmethod
    def register(self, plugin: ScannerPluginPort) -> None:
        """Register a scanner plugin.

        The plugin must implement ``ScannerPluginPort``. Registration
        validates API version compatibility and checks availability.

        Args:
            plugin: A ScannerPluginPort implementation.

        Raises:
            ScannerDuplicateError: If a plugin with the same ScannerId
                is already registered.
            ScannerVersionError: If the plugin targets an incompatible
                API version.
        """
        ...

    @abstractmethod
    def get(self, plugin_id: ScannerId) -> ScannerPluginPort:
        """Return the registered plugin for the given id.

        Args:
            plugin_id: The ScannerId to look up.

        Raises:
            ScannerPluginError: If no plugin is registered for this id.
        """
        ...

    @abstractmethod
    def resolve(self, target: Target) -> tuple[ScannerPluginPort, ...]:
        """Return all plugins capable of scanning this target type.

        Returns an empty tuple if no plugins match. The orchestrator
        calls this before execution to build the candidate list.

        Resolution order:
        1. Plugins whose capabilities include the target's type.
        2. Ordered by scan category priority (VULNERABILITY first).
        3. Ordered by number of matching target types (most specific first).
        """
        ...

    @abstractmethod
    def is_compatible(self, scanner_id: ScannerId, target_type: TargetType) -> bool:
        """Return whether a specific scanner declares support for a target type.

        The single source of truth for scanner/target-type compatibility.
        ``resolve()`` is defined in terms of this method, and
        ``ExecutionPlanner.plan()`` must call this method directly rather
        than re-deriving compatibility itself — this is what keeps the
        planner's selection and the orchestrator's execution from ever
        drifting apart again (Phase 2A Correction 2).

        Returns ``False`` for an unregistered scanner_id rather than
        raising — an unknown scanner is, definitionally, not compatible
        with anything.
        """
        ...

    @abstractmethod
    def list_all(self) -> tuple[tuple[ScannerPluginMetadata, PluginAvailability], ...]:
        """Return metadata and availability for every registered plugin.

        Used for status endpoints and administrative views. The returned
        tuples are snapshots — availability may change between calls.
        """
        ...
