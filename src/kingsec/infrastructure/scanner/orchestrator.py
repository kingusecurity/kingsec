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

from kingsec.application._support import safe_failure_message
from kingsec.application.assessment_execution import AssessmentExecutionEngine
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
from kingsec.infrastructure.scanner.errors import ScannerExecutionError

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

        ``ScannerPluginError`` is propagated unchanged (already a
        deliberately-authored, safe-by-construction message - the same
        convention ``safe_failure_message()`` applies elsewhere). Any other
        exception is wrapped in ``ScannerPluginError``, but the ORIGINAL
        exception's text never enters the wrapper's message verbatim: it is
        sanitized here, at the one point the real exception type is still
        available, via ``safe_failure_message()`` - the same three-branch
        split (``KingSecError.user_message`` / safe ``ApplicationError`` text
        / generic fallback) Phase 03 established. Doing it here, not at each
        downstream consumer, is what lets a safe message stay informative
        instead of every failure collapsing to one generic string.
        """
        try:
            p = cast(ScannerPluginPort, plugin)
            p.health_check()
            return p.scan(target, config)
        except ScannerPluginError:
            raise
        except Exception as exc:
            p2 = cast(ScannerPluginPort, plugin)
            raise ScannerPluginError(
                f"unexpected error in plugin {p2.metadata().id.value!r}: {safe_failure_message(exc)}"
            ) from exc

    def execute_all(
        self,
        target: Target,
        configs: dict[ScannerId, PluginConfig] | None = None,
        scanner_ids: Sequence[str] | None = None,
        execution_engine: AssessmentExecutionEngine | None = None,
        tracking_id: str | None = None,
    ) -> tuple[ScannerResult, ...]:
        """Execute plugins for a target.

        Phase 2A Correction 2c: when ``scanner_ids`` is given (the normal,
        profile-driven path), this method executes EXACTLY that set and
        performs NO further target-type filtering of its own — that
        decision was already made, once, by ``ExecutionPlanner.plan()``
        (Correction 2a/2b), which is now the single source of truth. A
        ``scanner_ids`` entry that cannot be resolved to a registered
        plugin is a bug in that invariant, not a run-time skip condition:
        it is raised, never silently dropped (Correction 2d — the planner
        and orchestrator's selected sets must always be identical, and a
        violation must fail loudly).

        ``scanner_ids=None`` is the legacy, no-profile fallback path
        (``StartAssessment``'s direct ``scan()`` call, unreached via any
        HTTP route) — unchanged: every target-compatible plugin runs, via
        the registry's own resolution, since there is no plan to be the
        source of truth here.

        Per-plugin runtime errors (including an unavailable/missing tool)
        are logged and that plugin's result is skipped — execution
        continues with the remaining plugins, the same graceful-
        degradation contract already used by ``shutdown()``. A
        subprocess-timeout error is reported to the execution engine as
        TIMED_OUT, distinct from any other FAILED outcome (Phase 2A FIX 1
        / Correction 3).

        When ``execution_engine`` and ``tracking_id`` are both given, each
        plugin's start/completion/failure/timeout is reported to the
        engine as it happens, so a caller can read back the real final
        per-scanner outcome after this call returns.
        """
        if scanner_ids is not None:
            plugins: tuple[ScannerPluginPort, ...] = tuple(
                self._registry.get(ScannerId(sid)) for sid in scanner_ids
            )
        else:
            plugins = self._registry.resolve(target)
            if not plugins:
                _logger.warning(
                    "no scanner plugin is compatible with this target type; "
                    "scan will produce zero findings",
                    target_type=str(target.type),
                )
        results: list[ScannerResult] = []
        engine, tid = execution_engine, tracking_id

        for plugin in plugins:
            plugin_id = plugin.metadata().id
            config = (configs or {}).get(plugin_id, PluginConfig())

            if engine is not None and tid is not None:
                engine.start_scanner(tid, plugin_id.value)

            try:
                result = self.execute(plugin, target, config)
                results.append(result)
                if engine is not None and tid is not None:
                    engine.complete_scanner(
                        tid,
                        plugin_id.value,
                        findings_count=len(result.findings),
                        warnings=result.warnings,
                    )
            except Exception as exc:
                # `exc` here is the (now-sanitized, per execute()'s own
                # wrapping above) ScannerPluginError. Its __cause__ is the
                # real, original exception when execute() wrapped one - log
                # THAT in full for operators (logging is unaffected by this
                # phase's sanitization; the redaction processor is the
                # correct, separate layer for secrets in log output), while
                # the product-facing engine call only ever sees the
                # already-sanitized wrapper text.
                original = exc.__cause__ if exc.__cause__ is not None else exc
                is_timeout = (
                    isinstance(original, ScannerExecutionError) and "timeout_seconds" in original.context
                )
                _logger.warning(
                    "scanner plugin timed out" if is_timeout else "scanner plugin failed, skipping",
                    plugin_id=str(plugin_id),
                    error=str(original),
                )
                if engine is not None and tid is not None:
                    if is_timeout:
                        engine.timeout_scanner(tid, plugin_id.value, safe_failure_message(exc))
                    else:
                        engine.fail_scanner(tid, plugin_id.value, safe_failure_message(exc))

        return tuple(results)

    # -- ScannerPort ---------------------------------------------------------

    def scan(self, target: Target, scanner_ids: Sequence[str] | None = None) -> Sequence[Finding]:
        """Scan ``target`` by executing all compatible plugins.

        Satisfies the ``ScannerPort`` contract. Flattens all findings from
        all successful plugin results into a single tuple.
        """
        results = self.execute_all(target, scanner_ids=scanner_ids)
        findings: list[Finding] = []
        for result in results:
            findings.extend(result.findings)
        return tuple(findings)

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        """Return the plugins ``scan()`` would attempt for ``target``.

        Reuses the same registry resolution ``execute_all`` uses
        internally, so this always reflects exactly what a subsequent
        ``scan()`` call against the same target would run.
        """
        return {p.metadata().id.value: p.metadata().name for p in self._registry.resolve(target)}

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
