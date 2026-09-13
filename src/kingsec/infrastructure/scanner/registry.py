"""In-memory scanner plugin registry.

Stores registered plugins in a plain ``dict`` keyed by ``ScannerId``.
No globals, no singletons, no module state — the instance owns its data.

This is the first infrastructure implementation of the
``ScannerPluginRegistry`` port. It handles registration, lookup,
and capability-based resolution. It does NOT handle execution,
lifecycle, or orchestration.
"""

from __future__ import annotations

from kingsec.application.errors import ScannerDuplicateError, ScannerPluginError
from kingsec.application.ports.scanner_plugin import ScannerPluginPort
from kingsec.application.ports.scanner_registry import ScannerPluginRegistry
from kingsec.domain import PluginAvailability, ScannerId, ScannerPluginMetadata, Target, TargetType
from kingsec.domain.scanner import provided_requirements


class InMemoryPluginRegistry(ScannerPluginRegistry):
    """A simple in-memory catalog of scanner plugins."""

    def __init__(self) -> None:
        self._plugins: dict[ScannerId, ScannerPluginPort] = {}

    def register(self, plugin: ScannerPluginPort) -> None:
        """Register a scanner plugin.

        Args:
            plugin: A ScannerPluginPort implementation.

        Raises:
            ScannerDuplicateError: If a plugin with the same ScannerId
                is already registered.
        """
        meta = plugin.metadata()
        plugin_id = meta.id

        if plugin_id in self._plugins:
            raise ScannerDuplicateError(f"scanner plugin {plugin_id.value!r} is already registered")

        self._plugins[plugin_id] = plugin

    def get(self, plugin_id: ScannerId) -> ScannerPluginPort:
        """Return the registered plugin for the given id.

        Args:
            plugin_id: The ScannerId to look up.

        Raises:
            ScannerPluginError: If no plugin is registered for this id.
        """
        try:
            return self._plugins[plugin_id]
        except KeyError:
            raise ScannerPluginError(f"no scanner plugin registered for {plugin_id.value!r}") from None

    def is_compatible(self, scanner_id: ScannerId, target_type: TargetType) -> bool:
        """Return whether a specific scanner declares support for a target type.

        The single source of truth — see the port docstring. ``resolve()``
        below is defined purely in terms of this method.

        Phase 2B Task 2: compatibility is now requirement-based - a target
        type is compatible with a scanner if the target type can PROVIDE
        (``provided_requirements()``, domain/scanner.py) at least one of
        the requirements the scanner's capabilities declare it NEEDS. The
        signature is unchanged from Phase 2A; only this method's internal
        data source changed, so both existing callers (the planner and the
        orchestrator's fallback path) keep working without modification.
        """
        plugin = self._plugins.get(scanner_id)
        if plugin is None:
            return False
        provided = provided_requirements(target_type)
        return any(cap.requirement in provided for cap in plugin.capabilities())

    def resolve(self, target: Target) -> tuple[ScannerPluginPort, ...]:
        """Return all plugins capable of scanning this target type.

        Checks each plugin's declared capabilities against the target's type
        via ``is_compatible()``. Returns an empty tuple if no plugins match.
        No ordering is applied.

        Args:
            target: The target whose type is matched against plugin capabilities.

        Returns:
            A tuple of matching ScannerPluginPort implementations.
        """
        return tuple(
            plugin
            for plugin_id, plugin in self._plugins.items()
            if self.is_compatible(plugin_id, target.type)
        )

    def list_all(
        self,
    ) -> tuple[tuple[ScannerPluginMetadata, PluginAvailability], ...]:
        """Return metadata and availability for every registered plugin.

        Calls ``plugin.is_available()`` for each plugin to capture a
        point-in-time snapshot of availability.

        Returns:
            A tuple of (metadata, availability) pairs.
        """
        return tuple((plugin.metadata(), plugin.is_available()) for plugin in self._plugins.values())
