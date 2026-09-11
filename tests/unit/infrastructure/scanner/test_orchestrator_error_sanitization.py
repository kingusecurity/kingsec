"""Phase 07: reproduction + regression for source-level scanner error sanitization.

Phase 06 §3.3 sanitized execution_routes.py's `error` field by collapsing
every value to a generic string - but the raw text was still being recorded
in the first place (ScannerOrchestrator.execute_all() -> engine.fail_scanner())
and still reached a second sink (assessment.scanner_summary, Phase 06 §5).
This file proves the fix at the true source: ScannerOrchestrator.execute()'s
exception wrapping (orchestrator.py:63-71) and execute_all()'s
engine.fail_scanner() call (orchestrator.py:135).

Written FIRST, before any fix, per Phase 07's ground rule #2. Run against
unmodified code, these fail because raw exception text is currently
interpolated verbatim into the ScannerPluginError wrapper's own message.
"""

from __future__ import annotations

from kingsec.application.assessment_execution import AssessmentExecutionEngine
from kingsec.application.errors import ScannerPluginError
from kingsec.domain import (
    OutputFormat,
    PluginAvailability,
    PluginConfig,
    ScanCategory,
    ScannerCapability,
    ScannerId,
    ScannerPluginMetadata,
    ScannerResult,
    Target,
    TargetType,
)
from kingsec.domain.enums import ScannerRunState
from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry
from kingsec.shared.errors import ScannerError

_TARGET = Target("10.0.0.5", TargetType.IP_ADDRESS)


class _StubPlugin:
    def __init__(self, plugin_id: str, raise_on_scan: Exception) -> None:
        self._id = plugin_id
        self._raise_on_scan = raise_on_scan

    def metadata(self) -> ScannerPluginMetadata:
        return ScannerPluginMetadata(
            id=ScannerId(self._id),
            name=f"{self._id.title()} Scanner",
            version="1.0.0",
            author="Test",
            description="stub",
            api_version="1.0",
        )

    def capabilities(self) -> tuple[ScannerCapability, ...]:
        return (
            ScannerCapability(
                target_types=frozenset({TargetType.IP_ADDRESS}),
                scan_categories=frozenset({ScanCategory.VULNERABILITY}),
                output_format=OutputFormat.FINDINGS,
            ),
        )

    def is_available(self) -> PluginAvailability:
        return PluginAvailability(available=True)

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        raise self._raise_on_scan

    def health_check(self) -> None:
        pass

    def shutdown(self) -> None:
        pass


class TestExecuteWrappingIsSanitized:
    """Directly exercises ScannerOrchestrator.execute() - the wrapping site."""

    def test_unvetted_exception_wrapped_message_has_no_raw_text(self) -> None:
        orchestrator = ScannerOrchestrator(InMemoryPluginRegistry())
        plugin = _StubPlugin("nuclei", ConnectionError("Connection refused: internal-scanner.corp.local:9200"))

        try:
            orchestrator.execute(plugin, _TARGET, PluginConfig())
            raise AssertionError("expected ScannerPluginError")
        except ScannerPluginError as exc:
            assert "internal-scanner.corp.local" not in str(exc)
            assert "9200" not in str(exc)

    def test_kingsec_error_wrapped_message_uses_safe_user_message(self) -> None:
        orchestrator = ScannerOrchestrator(InMemoryPluginRegistry())
        inner = ScannerError("subprocess /opt/scanners/nuclei failed: Permission denied: /etc/nuclei/config")
        plugin = _StubPlugin("nuclei", inner)

        try:
            orchestrator.execute(plugin, _TARGET, PluginConfig())
            raise AssertionError("expected ScannerPluginError")
        except ScannerPluginError as exc:
            assert "/opt/scanners" not in str(exc)
            assert "The security scan could not be completed." in str(exc)

    def test_deliberately_raised_scanner_plugin_error_is_preserved_verbatim(self) -> None:
        # Case 1 from Phase 07 §2.1: a plugin that raises ScannerPluginError
        # itself is re-raised unchanged by execute() (no wrapping happens at
        # all) - already safe by construction, must not be touched.
        orchestrator = ScannerOrchestrator(InMemoryPluginRegistry())
        plugin = _StubPlugin("nmap", ScannerPluginError("'Nmap' is not installed"))

        try:
            orchestrator.execute(plugin, _TARGET, PluginConfig())
            raise AssertionError("expected ScannerPluginError")
        except ScannerPluginError as exc:
            assert str(exc) == "'Nmap' is not installed"


class TestFailScannerReceivesSanitizedText:
    def test_engine_records_safe_message_not_raw_text(self) -> None:
        registry = InMemoryPluginRegistry()
        registry.register(_StubPlugin("nuclei", ConnectionError("Connection refused: internal-scanner.corp.local:9200")))
        orchestrator = ScannerOrchestrator(registry)
        engine = AssessmentExecutionEngine()
        engine.start_execution("asmt-1", {"nuclei": "Nuclei Scanner"})

        orchestrator.execute_all(_TARGET, execution_engine=engine, tracking_id="asmt-1")

        state = engine.get_state("asmt-1")
        assert state is not None
        entry = next(p for p in state.scanner_progress if p.scanner_id == "nuclei")
        assert entry.status == ScannerRunState.FAILED
        assert entry.error is not None
        assert "internal-scanner.corp.local" not in entry.error
        assert "9200" not in entry.error


