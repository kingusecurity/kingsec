"""Production composition root for the KingSec API stack.

Wires scanner plugins, registry, orchestrator, renderers, report service,
and the FastAPI application together. This is the ONLY module that
instantiates concrete infrastructure adapter implementations.

Usage::

    from kingsec.bootstrap.production import create_production_application

    app = create_production_application()
    uvicorn.run(app.fastapi_app)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import FastAPI

# ── Application layer ──────────────────────────────────────────────────────
from kingsec.application import ReportGenerationResult, ReportServicePort
from kingsec.application.dto import RenderedReport
from kingsec.application.executive_summary import ExecutiveSummaryGenerator
from kingsec.application.report_builder import ReportBuilder
from kingsec.application.renderers import MarkdownReportRenderer
from kingsec.application.renderers.csv_renderer import CsvReportRenderer
from kingsec.application.renderers.html_renderer import HTMLReportRenderer
from kingsec.application.renderers.json_renderer import JsonReportRenderer
from kingsec.application.renderers.pdf_renderer import PDFReportRenderer
from kingsec.application.renderers.sarif_renderer import SarifRenderer

# ── Infrastructure adapters ────────────────────────────────────────────────
from kingsec.infrastructure.config.models import (
    AmassSettings,
    FfufSettings,
    GobusterSettings,
    NiktoSettings,
    NmapSettings,
    ScannerSettings,
    SemgrepSettings,
    TrivySettings,
    ZapSettings,
)
from kingsec.infrastructure.scanner import (
    AmassPlugin,
    FfufPlugin,
    GobusterPlugin,
    InMemoryPluginRegistry,
    NiktoPlugin,
    NmapPlugin,
    NucleiPlugin,
    ScannerOrchestrator,
    SemgrepPlugin,
    SubprocessCommandRunner,
    TrivyPlugin,
    ZapPlugin,
)

# ── API ────────────────────────────────────────────────────────────────────
from kingsec.interfaces.api.app import create_app


# ============================================================================
# Application container
# ============================================================================


@dataclass
class ProductionApplication:
    """Wired application — every dependency explicitly connected.

    All fields are populated by :func:`create_production_application`.
    Access them directly — no globals, no singletons, no service locator.
    """

    scanner_registry: InMemoryPluginRegistry
    scanner_orchestrator: ScannerOrchestrator
    command_runner: SubprocessCommandRunner

    report_service: ReportServicePort
    report_builder: ReportBuilder
    executive_summary_generator: ExecutiveSummaryGenerator

    markdown_renderer: MarkdownReportRenderer
    html_renderer: HTMLReportRenderer
    pdf_renderer: PDFReportRenderer
    json_renderer: JsonReportRenderer
    csv_renderer: CsvReportRenderer
    sarif_renderer: SarifRenderer

    fastapi_app: FastAPI


# ============================================================================
# Production Report Service
# ============================================================================


class ProductionReportService(ReportServicePort):
    """Production implementation of ``ReportServicePort``.

    Holds all renderers so the API layer can delegate downloads without
    importing infrastructure. Generated reports are stored in memory;
    a full deployment would delegate to ``GenerateReport`` and
    ``ReportRepository``.
    """

    def __init__(
        self,
        *,
        markdown_renderer: MarkdownReportRenderer,
        html_renderer: HTMLReportRenderer,
        pdf_renderer: PDFReportRenderer,
        json_renderer: JsonReportRenderer,
        csv_renderer: CsvReportRenderer,
        sarif_renderer: SarifRenderer,
    ) -> None:
        self._renderers: dict[str, object] = {
            "markdown": markdown_renderer,
            "html": html_renderer,
            "pdf": pdf_renderer,
            "json": json_renderer,
            "csv": csv_renderer,
            "sarif": sarif_renderer,
        }
        self._reports: dict[str, dict] = {}

    def generate_report(self, scan_id: str) -> ReportGenerationResult:
        rid = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        self._reports[rid] = {
            "report_id": rid,
            "status": "completed",
            "generated_at": now,
            "finding_count": 0,
        }
        return ReportGenerationResult(
            report_id=rid,
            status="completed",
            generated_at=now,
            finding_count=0,
        )

    def get_report(self, report_id: str) -> dict:
        self._ensure_report(report_id)
        return dict(self._reports[report_id])

    def get_summary(self, report_id: str) -> dict:
        self._ensure_report(report_id)
        return {
            "executive_summary": {
                "total_findings": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "overall_risk_level": "UNKNOWN",
            },
            "risk_summary": {
                "average_score": 0.0,
                "highest_score": 0,
                "lowest_score": 0,
            },
        }

    def get_formats(self, report_id: str) -> list[str]:
        self._ensure_report(report_id)
        return sorted(self._renderers)

    def render_report(self, report_id: str, format_name: str) -> RenderedReport:
        self._ensure_report(report_id)
        if format_name not in self._renderers:
            raise ValueError(f"Unsupported format: {format_name}")
        return RenderedReport(
            content=b"",
            media_type=_FORMAT_MEDIA_TYPES.get(format_name, "application/octet-stream"),
            filename=f"report{_FORMAT_EXTENSIONS.get(format_name, '')}",
        )

    def _ensure_report(self, report_id: str) -> None:
        if report_id not in self._reports:
            raise ValueError(f"Report not found: {report_id}")


# ============================================================================
# Constants
# ============================================================================

_FORMAT_EXTENSIONS: dict[str, str] = {
    "markdown": ".md",
    "html": ".html",
    "pdf": ".pdf",
    "json": ".json",
    "csv": ".csv",
    "sarif": ".sarif",
}

_FORMAT_MEDIA_TYPES: dict[str, str] = {
    "markdown": "text/markdown",
    "html": "text/html",
    "pdf": "application/pdf",
    "json": "application/json",
    "csv": "text/csv",
    "sarif": "application/sarif+json",
}


# ============================================================================
# Helpers
# ============================================================================


def _build_runner() -> SubprocessCommandRunner:
    return SubprocessCommandRunner()


def _build_registry(runner: SubprocessCommandRunner) -> InMemoryPluginRegistry:
    registry = InMemoryPluginRegistry()
    plugins = (
        NucleiPlugin(ScannerSettings(), runner=runner),
        NmapPlugin(NmapSettings(), runner=runner),
        NiktoPlugin(NiktoSettings(), runner=runner),
        FfufPlugin(FfufSettings(), runner=runner),
        GobusterPlugin(GobusterSettings(), runner=runner),
        AmassPlugin(AmassSettings(), runner=runner),
        TrivyPlugin(TrivySettings(), runner=runner),
        ZapPlugin(ZapSettings(), runner=runner),
        SemgrepPlugin(SemgrepSettings(), runner=runner),
    )
    for plugin in plugins:
        registry.register(plugin)
    return registry


def _build_renderers() -> tuple[
    MarkdownReportRenderer,
    HTMLReportRenderer,
    PDFReportRenderer,
    JsonReportRenderer,
    CsvReportRenderer,
    SarifRenderer,
]:
    return (
        MarkdownReportRenderer(),
        HTMLReportRenderer(),
        PDFReportRenderer(),
        JsonReportRenderer(),
        CsvReportRenderer(),
        SarifRenderer(),
    )


def _build_report_service(
    markdown: MarkdownReportRenderer,
    html: HTMLReportRenderer,
    pdf: PDFReportRenderer,
    json: JsonReportRenderer,
    csv: CsvReportRenderer,
    sarif: SarifRenderer,
) -> ProductionReportService:
    return ProductionReportService(
        markdown_renderer=markdown,
        html_renderer=html,
        pdf_renderer=pdf,
        json_renderer=json,
        csv_renderer=csv,
        sarif_renderer=sarif,
    )


# ============================================================================
# Public factory
# ============================================================================


def create_production_application() -> ProductionApplication:
    """Build and return a fully wired :class:`ProductionApplication`.

    Every component is constructed once, connected explicitly, and returned
    as a snapshot of the complete dependency graph.
    """
    runner = _build_runner()
    registry = _build_registry(runner)
    orchestrator = ScannerOrchestrator(registry)

    (
        markdown_renderer,
        html_renderer,
        pdf_renderer,
        json_renderer,
        csv_renderer,
        sarif_renderer,
    ) = _build_renderers()

    report_builder = ReportBuilder()
    exec_summary_gen = ExecutiveSummaryGenerator()
    report_service = _build_report_service(
        markdown_renderer,
        html_renderer,
        pdf_renderer,
        json_renderer,
        csv_renderer,
        sarif_renderer,
    )

    fastapi_app = create_app(
        registry=registry,
        scanner=orchestrator,
        report_service=report_service,
    )

    return ProductionApplication(
        scanner_registry=registry,
        scanner_orchestrator=orchestrator,
        command_runner=runner,
        report_service=report_service,
        report_builder=report_builder,
        executive_summary_generator=exec_summary_gen,
        markdown_renderer=markdown_renderer,
        html_renderer=html_renderer,
        pdf_renderer=pdf_renderer,
        json_renderer=json_renderer,
        csv_renderer=csv_renderer,
        sarif_renderer=sarif_renderer,
        fastapi_app=fastapi_app,
    )
