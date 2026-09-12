"""Phase 07: report-layer reproduction + regression for source sanitization.

Confirms §2.2's downstream quality check with real values: once
ScannerOrchestrator sanitizes at source, the report's Scanner Coverage
section (templates.py's _scanner_summary()/_clean_scanner_reason()) renders
a safe message for a developer-authored failure and a generic fallback for
an unvetted one - improving on the unvetted case without degrading the
developer-authored one, using REAL summaries produced by the real
orchestrator rather than hand-typed strings.

Written FIRST, before any fix, per Phase 07's ground rule #2.
"""

from __future__ import annotations

from kingsec.domain import (
    Assessment,
    Authorization,
    OutputFormat,
    PluginAvailability,
    PluginConfig,
    Report,
    ScanCategory,
    ScannerCapability,
    ScannerId,
    ScannerPluginMetadata,
    ScannerRequirement,
    ScannerResult,
    Target,
    TargetType,
)
from kingsec.infrastructure.reporting.templates import render_report_html
from kingsec.infrastructure.scanner.errors import ScannerExecutionError
from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry


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


def _real_scanner_summary(exc: Exception) -> tuple:
    """Run the real orchestrator against a single failing plugin and return
    the real ScannerRunSummary it would produce (mirrors submit_assessment.py's
    own ran_summaries construction, without needing the full use case)."""
    from kingsec.application.assessment_execution import AssessmentExecutionEngine
    from kingsec.domain import ScannerRunSummary

    registry = InMemoryPluginRegistry()
    registry.register(_StubPlugin("nuclei", exc))
    orchestrator = ScannerOrchestrator(registry)
    engine = AssessmentExecutionEngine()
    engine.start_execution("asmt-1", {"nuclei": "Nuclei Scanner"})

    orchestrator.execute_all(Target("10.0.0.5", TargetType.IP_ADDRESS), execution_engine=engine, tracking_id="asmt-1")

    state = engine.get_state("asmt-1")
    assert state is not None
    return tuple(
        ScannerRunSummary(
            scanner_id=p.scanner_id,
            name=p.name,
            status=p.status,
            findings_count=p.findings_count,
            skipped_reason=p.skipped_reason or p.error,
        )
        for p in state.scanner_progress
    )


def _build_report(scanner_summary: tuple) -> Report:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessment.start()
    assessment.record_scanner_summary(scanner_summary)
    assessment.complete()
    return Report.from_assessment(assessment)


class TestScannerCoverageRendersSafely:
    def test_unvetted_failure_renders_generic_fallback_no_hostname(self) -> None:
        summary = _real_scanner_summary(ConnectionError("Connection refused: internal-scanner.corp.local:9200"))
        html = render_report_html(_build_report(summary))
        section = html.split('id="scanner-coverage"')[1].split("</section>")[0]

        assert "internal-scanner.corp.local" not in section
        assert "An unexpected error occurred" in section or "did not complete" in section

    def test_developer_authored_failure_renders_useful_safe_message(self) -> None:
        exc = ScannerExecutionError("nuclei exited with code 1", context={"returncode": 1})
        summary = _real_scanner_summary(exc)
        html = render_report_html(_build_report(summary))
        section = html.split('id="scanner-coverage"')[1].split("</section>")[0]

        assert "The security scan could not be completed" in section
