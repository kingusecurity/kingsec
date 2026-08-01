"""Scanner orchestrator: bridges the plugin framework with the application.

Implements both ``ScannerPort`` (the existing use-case contract) and
``ScannerExecutor`` (the new plugin lifecycle contract). This class is the
single point through which all scanning flows — use cases call ``scan()``,
and the executor calls ``execute()`` / ``execute_all()``.

No existing use case changes. The orchestrator delegates to plugins resolved
by the registry and flattens their results into the ``ScannerPort`` contract.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast

from kingsec.application.errors import ScannerPluginError
from kingsec.application.ports.scanner_executor import ScannerExecutor
from kingsec.application.ports.scanner_plugin import ScannerPluginPort
from kingsec.application.ports.scanner_registry import ScannerPluginRegistry
from kingsec.application.ports.services import ScannerPort
from kingsec.domain import (
    Finding,
    PluginConfig,
    ScannerId,
    ScannerResult,
    Target,
)
from kingsec.infrastructure.logging import get_logger

_logger = get_logger("kingsec.infrastructure.scanner.orchestrator")


class ScannerOrchestrator(ScannerPort, ScannerExecutor):
    """Delegates scanning to registered plugins via the registry.

    Injects only a ``ScannerPluginRegistry`` — no globals, no service
    locator, no singleton. The registry owns plugin lookup; the
    orchestrator owns execution and result flattening.
    """

    def __init__(self, registry: ScannerPluginRegistry) -> None:
        self._registry = registry

    # -- ScannerExecutor -----------------------------------------------------

    def execute(
        self,
        plugin: object,
        target: Target,
        config: PluginConfig,
    ) -> ScannerResult:
        """Execute a single plugin against a target.

        1. Calls ``plugin.health_check()`` to verify readiness.
        2. Calls ``plugin.scan(target, config)``.
        3. Returns the ``ScannerResult``.

        ``ScannerPluginError`` is propagated unchanged. Any other exception
        is wrapped in ``ScannerPluginError`` with chaining.
        """
        try:
            p = cast(ScannerPluginPort, plugin)
            p.health_check()
            return p.scan(target, config)
        except ScannerPluginError:
            raise
        except Exception as exc:
            p2 = cast(ScannerPluginPort, plugin)
            raise ScannerPluginError(f"unexpected error in plugin {p2.metadata().id.value!r}: {exc}") from exc

    def execute_all(
        self,
        target: Target,
        configs: dict[ScannerId, PluginConfig] | None = None,
    ) -> tuple[ScannerResult, ...]:
        """Execute all compatible plugins for a target.

        Iterates over plugins resolved by the registry. Per-plugin errors
        (including an unavailable/missing tool) are logged and that plugin
        is skipped — execution continues with the remaining plugins, the
        same graceful-degradation contract already used by ``shutdown()``.
        """
        plugins = self._registry.resolve(target)
        results: list[ScannerResult] = []

        for plugin in plugins:
            plugin_id = plugin.metadata().id
            config = (configs or {}).get(plugin_id, PluginConfig())

            try:
                result = self.execute(plugin, target, config)
                results.append(result)
            except Exception as exc:
                _logger.warning(
                    "scanner plugin failed, skipping",
                    plugin_id=str(plugin_id),
                    error=str(exc),
                )

        return tuple(results)

    # -- ScannerPort ---------------------------------------------------------

    def scan(self, target: Target) -> Sequence[Finding]:
        """Scan ``target`` by executing all compatible plugins.

        Satisfies the ``ScannerPort`` contract. Flattens all findings from
        all successful plugin results into a single tuple.
        """
        results = self.execute_all(target)
        findings: list[Finding] = []
        for result in results:
            findings.extend(result.findings)
        return tuple(findings)

    # -- Lifecycle -----------------------------------------------------------

    def shutdown(self) -> None:
        """Shut down every registered plugin.

        Calls ``plugin.shutdown()`` for each plugin. Ignores unavailable
        plugins and continues even if a shutdown call fails. Never raises.
        """
        for plugin_metadata, availability in self._registry.list_all():
            if not availability.available:
                continue
            plugin = self._registry.get(plugin_metadata.id)
            try:
                plugin.shutdown()
            except Exception:
                _logger.warning(
                    "plugin shutdown failed",
                    plugin_id=str(plugin_metadata.id),
                )
