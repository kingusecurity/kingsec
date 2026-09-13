"""Phase 07: proves source-level scanner error sanitization does not suppress
structured logging.

orchestrator.py's module-level `_logger` is bound once at import via
structlog.get_logger(...).bind(...), and this codebase's own
cache_logger_on_first_use=True (logger.py) means that binding survives
whichever test happened to log through it first in the pytest session -
neither reconfiguring the real stream/configure pipeline nor
structlog.testing.capture_logs() reliably intercepts it per-test (both
verified empirically not to work here). This test instead monkeypatches
orchestrator.py's `_logger` attribute directly for the duration of the test
and asserts on the call arguments - a legitimate, sufficient check for what
this phase actually needs to prove (the code still PASSES the raw detail to
the logging call), independent of structlog's own global caching behavior,
which is untouched by and orthogonal to this phase's change.
"""

from __future__ import annotations

from kingsec.domain import (
    OutputFormat,
    PluginAvailability,
    PluginConfig,
    ScanCategory,
    ScannerCapability,
    ScannerId,
    ScannerPluginMetadata,
    ScannerRequirement,
    ScannerResult,
    Target,
    TargetType,
)
from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry

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
                requirement=ScannerRequirement.REACHABLE_HOST,
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


class _RecordingLogger:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def warning(self, event: str, **kwargs: object) -> None:
        self.calls.append((event, kwargs))

    def info(self, event: str, **kwargs: object) -> None:
        pass


class TestLoggingStillReceivesRawDetail:
    def test_orchestrator_still_logs_the_raw_hostname(self, monkeypatch) -> None:
        import kingsec.infrastructure.scanner.orchestrator as orchestrator_module

        fake_logger = _RecordingLogger()
        monkeypatch.setattr(orchestrator_module, "_logger", fake_logger)

        registry = InMemoryPluginRegistry()
        registry.register(
            _StubPlugin("nuclei", ConnectionError("Connection refused: internal-scanner.corp.local:9200"))
        )
        orchestrator = ScannerOrchestrator(registry)

        orchestrator.execute_all(_TARGET)

        failure_calls = [c for c in fake_logger.calls if c[0] == "scanner plugin failed, skipping"]
        assert len(failure_calls) == 1
        assert "internal-scanner.corp.local" in failure_calls[0][1]["error"]
