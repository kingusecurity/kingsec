"""Outbound port: scanner executor.

The executor owns the full plugin lifecycle during scan execution:
health check, invocation, timeout enforcement, error isolation, and
result normalization. It does NOT own plugin selection (that is the
registry's job) or finding enrichment (that is the use case's job).

This separation keeps each component focused: registry = catalog,
executor = runner, use case = orchestrator of business logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from kingsec.application.assessment_execution import AssessmentExecutionEngine
from kingsec.domain import PluginConfig, ScannerId, ScannerResult, Target


class ScannerExecutor(ABC):
    """Runs scans through the full plugin lifecycle."""

    @abstractmethod
    def execute(
        self,
        plugin: object,
        target: Target,
        config: PluginConfig,
    ) -> ScannerResult:
        """Execute a single plugin against a target.

        The executor:
        1. Calls ``plugin.health_check()`` to verify readiness.
        2. Invokes ``plugin.scan(target, config)``.
        3. Enforces a hard timeout.
        4. Validates the returned ScannerResult.
        5. Catches plugin errors and translates them.

        Args:
            plugin: A ScannerPluginPort implementation.
            target: The validated domain target.
            config: Plugin-specific configuration.

        Returns:
            The normalized scan results.

        Raises:
            ScannerUnavailableError: If the plugin fails its health check.
            ScannerTimeoutError: If the scan exceeds the allowed time.
            ScannerPluginError: If the plugin raises an unexpected error.
        """
        ...

    @abstractmethod
    def execute_all(
        self,
        target: Target,
        configs: dict[ScannerId, PluginConfig] | None = None,
        scanner_ids: Sequence[str] | None = None,
        execution_engine: AssessmentExecutionEngine | None = None,
        tracking_id: str | None = None,
    ) -> tuple[ScannerResult, ...]:
        """Execute all compatible plugins for a target.

        Iterates over plugins resolved by the registry for the given
        target type, executes each, and merges results. Per-plugin
        errors are logged and skipped — one failure does not prevent
        other plugins from running.

        Args:
            target: The validated domain target.
            configs: Optional per-plugin configuration overrides.
                Keys are ScannerIds. Plugins not in this dict use
                their default configuration.
            scanner_ids: When given, narrows execution to this subset of
                otherwise-compatible plugins. ``None`` runs every
                compatible plugin, exactly as before this parameter
                existed.
            execution_engine: When given (together with ``tracking_id``),
                each plugin's start/completion/failure is reported to it
                in real time, so ``execution_engine.get_state(tracking_id)``
                reflects the true outcome once this call returns.
            tracking_id: The assessment id to report progress under.
                Ignored unless ``execution_engine`` is also given.

        Returns:
            A tuple of ScannerResult from all plugins that succeeded.
            If zero plugins succeed, returns an empty tuple (never None).
        """
        ...
