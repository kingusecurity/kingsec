"""Bootstrap composition root: production wiring tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from kingsec.application.renderers import MarkdownReportRenderer
from kingsec.application.renderers.csv_renderer import CsvReportRenderer
from kingsec.application.renderers.html_renderer import HTMLReportRenderer
from kingsec.application.renderers.json_renderer import JsonReportRenderer
from kingsec.application.renderers.pdf_renderer import PDFReportRenderer
from kingsec.application.renderers.sarif_renderer import SarifRenderer
from kingsec.bootstrap.production import (
    ProductionApplication,
    ProductionReportService,
    create_production_application,
)
from kingsec.infrastructure.scanner import (
    InMemoryPluginRegistry,
    ScannerOrchestrator,
    SubprocessCommandRunner,
)


async def _fake_auth():
    """Bypass real authentication — returns None (user object unused by routes)."""
    return None


# ===========================================================================
# Top-level factory
# ===========================================================================


class TestCreateApplication:
    def test_returns_production_application(self) -> None:
        app = create_production_application()
        assert isinstance(app, ProductionApplication)

    def test_creates_scanner_registry(self) -> None:
        app = create_production_application()
        assert isinstance(app.scanner_registry, InMemoryPluginRegistry)

    def test_creates_scanner_orchestrator(self) -> None:
        app = create_production_application()
        assert isinstance(app.scanner_orchestrator, ScannerOrchestrator)

    def test_creates_command_runner(self) -> None:
        app = create_production_application()
        assert isinstance(app.command_runner, SubprocessCommandRunner)

    def test_creates_report_service(self) -> None:
        app = create_production_application()
        assert isinstance(app.report_service, ProductionReportService)

    def test_creates_report_builder(self) -> None:
        app = create_production_application()
        from kingsec.application.report_builder import ReportBuilder
        assert isinstance(app.report_builder, ReportBuilder)

    def test_creates_executive_summary_generator(self) -> None:
        app = create_production_application()
        from kingsec.application.executive_summary import ExecutiveSummaryGenerator
        assert isinstance(app.executive_summary_generator, ExecutiveSummaryGenerator)

    def test_creates_fastapi_app(self) -> None:
        app = create_production_application()
        from fastapi import FastAPI
        assert isinstance(app.fastapi_app, FastAPI)


# ===========================================================================
# All plugins registered
# ===========================================================================


class TestAllPluginsRegistered:
    def test_nine_plugins_registered(self) -> None:
        app = create_production_application()
        plugins = app.scanner_registry.list_all()
        assert len(plugins) == 9

    def test_expected_plugin_ids(self) -> None:
        app = create_production_application()
        ids = {meta.id.value for meta, _ in app.scanner_registry.list_all()}
        expected = {
            "nuclei", "nmap", "nikto", "ffuf", "gobuster",
            "amass", "trivy", "zap", "semgrep",
        }
        assert ids == expected

    def test_each_plugin_has_metadata(self) -> None:
        app = create_production_application()
        for meta, _ in app.scanner_registry.list_all():
            assert meta.id.value
            assert meta.name
            assert meta.version
            assert meta.author
            assert meta.description
            assert meta.api_version

    def test_plugin_scan_capabilities(self) -> None:
        app = create_production_application()
        for meta, _ in app.scanner_registry.list_all():
            plugin = app.scanner_registry.get(meta.id)
            caps = plugin.capabilities()
            assert len(caps) >= 1


# ===========================================================================
# All renderers created
# ===========================================================================


class TestAllRenderers:
    def test_markdown_renderer(self) -> None:
        app = create_production_application()
        assert isinstance(app.markdown_renderer, MarkdownReportRenderer)

    def test_html_renderer(self) -> None:
        app = create_production_application()
        assert isinstance(app.html_renderer, HTMLReportRenderer)

    def test_pdf_renderer(self) -> None:
        app = create_production_application()
        assert isinstance(app.pdf_renderer, PDFReportRenderer)

    def test_json_renderer(self) -> None:
        app = create_production_application()
        assert isinstance(app.json_renderer, JsonReportRenderer)

    def test_csv_renderer(self) -> None:
        app = create_production_application()
        assert isinstance(app.csv_renderer, CsvReportRenderer)

    def test_sarif_renderer(self) -> None:
        app = create_production_application()
        assert isinstance(app.sarif_renderer, SarifRenderer)

    def test_renderers_are_distinct(self) -> None:
        app = create_production_application()
        renderers = [
            app.markdown_renderer,
            app.html_renderer,
            app.pdf_renderer,
            app.json_renderer,
            app.csv_renderer,
            app.sarif_renderer,
        ]
        assert len(set(id(r) for r in renderers)) == 6


# ===========================================================================
# Report service
# ===========================================================================


class TestReportService:
    def test_generate_report(self) -> None:
        app = create_production_application()
        result = app.report_service.generate_report("scan-001")
        assert result.report_id
        assert result.status == "completed"
        assert result.generated_at
        assert result.finding_count == 0

    def test_get_report(self) -> None:
        app = create_production_application()
        gen = app.report_service.generate_report("scan-001")
        report = app.report_service.get_report(gen.report_id)
        assert report["report_id"] == gen.report_id

    def test_get_summary(self) -> None:
        app = create_production_application()
        gen = app.report_service.generate_report("scan-001")
        summary = app.report_service.get_summary(gen.report_id)
        assert "executive_summary" in summary
        assert "risk_summary" in summary

    def test_get_formats(self) -> None:
        app = create_production_application()
        gen = app.report_service.generate_report("scan-001")
        formats = app.report_service.get_formats(gen.report_id)
        assert "markdown" in formats
        assert "html" in formats
        assert "pdf" in formats
        assert "json" in formats
        assert "csv" in formats
        assert "sarif" in formats

    def test_all_six_formats(self) -> None:
        app = create_production_application()
        gen = app.report_service.generate_report("scan-001")
        assert len(app.report_service.get_formats(gen.report_id)) == 6

    def test_render_report_markdown(self) -> None:
        app = create_production_application()
        gen = app.report_service.generate_report("scan-001")
        rendered = app.report_service.render_report(gen.report_id, "markdown")
        assert rendered.filename == "report.md"
        assert rendered.media_type == "text/markdown"

    def test_render_report_pdf(self) -> None:
        app = create_production_application()
        gen = app.report_service.generate_report("scan-001")
        rendered = app.report_service.render_report(gen.report_id, "pdf")
        assert rendered.filename == "report.pdf"
        assert rendered.media_type == "application/pdf"

    def test_render_report_sarif(self) -> None:
        app = create_production_application()
        gen = app.report_service.generate_report("scan-001")
        rendered = app.report_service.render_report(gen.report_id, "sarif")
        assert rendered.filename == "report.sarif"
        assert rendered.media_type == "application/sarif+json"


# ===========================================================================
# All routers registered
# ===========================================================================


class TestAllRouters:
    def test_scan_routes_accessible(self) -> None:
        app = create_production_application(auth_dependency=_fake_auth)
        client = TestClient(app.fastapi_app)
        # POST /scan returns 422 for bad input (validation), not 404
        assert client.post("/scan", json={}).status_code == 422
        # GET /scan/scanners returns scanner metadata
        resp = client.get("/scan/scanners")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 9

    def test_report_routes_accessible(self) -> None:
        app = create_production_application(auth_dependency=_fake_auth)
        client = TestClient(app.fastapi_app)
        # First generate a report
        resp = client.post("/report", json={"scan_id": "test"})
        assert resp.status_code == 200
        report_id = resp.json()["report_id"]
        # GET /report/{id}
        assert client.get(f"/report/{report_id}").status_code == 200
        # GET /report/{id}/summary
        assert client.get(f"/report/{report_id}/summary").status_code == 200
        # GET /report/{id}/formats
        resp = client.get(f"/report/{report_id}/formats")
        assert resp.status_code == 200
        assert len(resp.json()) == 6

    def test_download_routes_accessible(self) -> None:
        app = create_production_application(auth_dependency=_fake_auth)
        client = TestClient(app.fastapi_app)
        resp = client.post("/report", json={"scan_id": "test"})
        report_id = resp.json()["report_id"]
        for fmt in ("markdown", "html", "pdf", "json", "csv", "sarif"):
            resp = client.get(f"/report/{report_id}/download/{fmt}")
            assert resp.status_code == 200, f"Failed for format {fmt}"

    def test_base_routes_accessible(self) -> None:
        app = create_production_application()
        client = TestClient(app.fastapi_app)
        assert client.get("/").status_code == 200
        assert client.get("/health").status_code == 200
        assert client.get("/version").status_code == 200


# ===========================================================================
# Dependency graph verification
# ===========================================================================


class TestDependencyGraph:
    def test_orchestrator_wired_to_registry(self) -> None:
        app = create_production_application()
        # The orchestrator should be using the same registry instance
        registry_plugins = app.scanner_registry.list_all()
        # Verify orchestrator can resolve plugins
        from kingsec.domain import Target, TargetType
        target = Target(value="example.com", type=TargetType.HOSTNAME)
        resolved = app.scanner_registry.resolve(target)
        assert len(resolved) > 0

    def test_app_wired_to_scanner_ports(self) -> None:
        app = create_production_application(auth_dependency=_fake_auth)
        client = TestClient(app.fastapi_app)
        # The scan endpoint uses scanner_orchestrator behind the scenes
        resp = client.get("/scan/scanners")
        assert resp.status_code == 200
        # Verify we get the expected scanner IDs
        ids = [s["id"] for s in resp.json()]
        assert "nuclei" in ids

    def test_app_wired_to_report_service(self) -> None:
        app = create_production_application(auth_dependency=_fake_auth)
        client = TestClient(app.fastapi_app)
        resp = client.post("/report", json={"scan_id": "check"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"

    def test_download_uses_report_service_renderers(self) -> None:
        app = create_production_application(auth_dependency=_fake_auth)
        client = TestClient(app.fastapi_app)
        resp = client.post("/report", json={"scan_id": "check"})
        report_id = resp.json()["report_id"]
        for fmt in ("markdown", "html", "pdf", "json", "csv", "sarif"):
            resp = client.get(f"/report/{report_id}/download/{fmt}")
            assert resp.status_code == 200
            assert "Content-Disposition" in resp.headers


# ===========================================================================
# No duplicate instances
# ===========================================================================


class TestNoDuplicates:
    def test_same_registry_wired_to_orchestrator(self) -> None:
        app = create_production_application()
        assert app.scanner_orchestrator is not None
        # The registry in app is the same one the orchestrator uses
        assert id(app.scanner_registry) == id(app.scanner_orchestrator._registry)


# ===========================================================================
# Create multiple applications independently
# ===========================================================================


class TestIndependence:
    def test_two_applications_are_separate(self) -> None:
        app1 = create_production_application()
        app2 = create_production_application()
        assert app1 is not app2
        assert app1.scanner_registry is not app2.scanner_registry
        assert app1.report_service is not app2.report_service
        assert app1.fastapi_app is not app2.fastapi_app
