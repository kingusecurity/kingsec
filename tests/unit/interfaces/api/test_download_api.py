"""Report download API routes: comprehensive tests."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kingsec.application import (
    RenderedReport,
    ReportGenerationResult,
    ReportServicePort,
)
from kingsec.application.errors import ReportNotFoundError
from kingsec.interfaces.api.app import create_app

from .helpers import fake_get_current_user

# ---------------------------------------------------------------------------
# Mock port
# ---------------------------------------------------------------------------


class _MockReportService(ReportServicePort):
    """Simulates the report service for download testing."""

    def __init__(self) -> None:
        self._existing = {"report-001", "report-002"}

    def generate_report(self, scan_id: str) -> ReportGenerationResult:
        return ReportGenerationResult(
            report_id=f"report-{scan_id}",
            status="completed",
            generated_at=datetime(2025, 6, 15, 14, 30, 0, tzinfo=UTC),
            finding_count=5,
        )

    def get_report(self, report_id: str) -> dict:
        if report_id not in self._existing:
            raise ReportNotFoundError(f"Report not found: {report_id}")
        return {"report_id": report_id, "title": "Test"}

    def get_summary(self, report_id: str) -> dict:
        if report_id not in self._existing:
            raise ReportNotFoundError(f"Report not found: {report_id}")
        return {"executive_summary": {}, "risk_summary": {}}

    def get_formats(self, report_id: str) -> list[str]:
        if report_id not in self._existing:
            raise ReportNotFoundError(f"Report not found: {report_id}")
        return ["markdown", "html", "pdf", "json", "csv", "sarif"]

    def render_report(self, report_id: str, format_name: str) -> RenderedReport:
        if report_id not in self._existing:
            raise ReportNotFoundError(f"Report not found: {report_id}")

        content_map: dict[str, tuple[bytes, str, str]] = {
            "markdown": (
                b"# Security Assessment Report\n\n**Target:** example.com",
                "text/markdown",
                ".md",
            ),
            "html": (
                b"<html><body><h1>Security Assessment Report</h1></body></html>",
                "text/html",
                ".html",
            ),
            "pdf": (
                b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF",
                "application/pdf",
                ".pdf",
            ),
            "json": (
                b'{"report_id":"report-001","title":"Security Assessment Report"}',
                "application/json",
                ".json",
            ),
            "csv": (
                b"finding_id,title,severity\nf-1,Open SSH port,HIGH\n",
                "text/csv",
                ".csv",
            ),
            "sarif": (
                b'{"version":"2.1.0","$schema":"https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json","runs":[]}',
                "application/sarif+json",
                ".sarif",
            ),
        }

        if format_name not in content_map:
            raise ValueError(f"Unsupported format: {format_name}")

        content, media_type, ext = content_map[format_name]
        return RenderedReport(
            content=content,
            media_type=media_type,
            filename=f"report{ext}",
        )


_REPORT_SERVICE = _MockReportService()

_REPORT_APP = create_app(report_service=_REPORT_SERVICE, get_current_user=fake_get_current_user)
_BASE_APP = create_app()

_EXPECTED_FORMATS: dict[str, tuple[str, str]] = {
    "markdown": ("text/markdown", ".md"),
    "html": ("text/html", ".html"),
    "pdf": ("application/pdf", ".pdf"),
    "json": ("application/json", ".json"),
    "csv": ("text/csv", ".csv"),
    "sarif": ("application/sarif+json", ".sarif"),
}


# ===========================================================================
# Download endpoints — per-format
# ===========================================================================


class TestDownloadFormats:
    def setup_method(self) -> None:
        self.client = TestClient(_REPORT_APP)

    def _check_download(self, fmt: str, media_type: str, ext: str) -> None:
        response = self.client.get(f"/report/report-001/download/{fmt}")
        assert response.status_code == 200, f"Failed for format {fmt}"
        assert response.headers.get("content-type", "").startswith(media_type), (
            f"Expected {media_type} for {fmt}, got {response.headers.get('content-type')}"
        )
        expected_disp = f'attachment; filename="report{ext}"'
        assert response.headers.get("content-disposition") == expected_disp, (
            f"Expected {expected_disp} for {fmt}, got {response.headers.get('content-disposition')}"
        )

    def test_download_markdown(self) -> None:
        self._check_download("markdown", "text/markdown", ".md")

    def test_download_html(self) -> None:
        self._check_download("html", "text/html", ".html")

    def test_download_pdf(self) -> None:
        self._check_download("pdf", "application/pdf", ".pdf")

    def test_download_json(self) -> None:
        self._check_download("json", "application/json", ".json")

    def test_download_csv(self) -> None:
        self._check_download("csv", "text/csv", ".csv")

    def test_download_sarif(self) -> None:
        self._check_download("sarif", "application/sarif+json", ".sarif")

    def test_download_markdown_content(self) -> None:
        response = self.client.get("/report/report-001/download/markdown")
        assert b"# Security Assessment Report" in response.content

    def test_download_html_content(self) -> None:
        response = self.client.get("/report/report-001/download/html")
        assert b"<html>" in response.content

    def test_download_pdf_content(self) -> None:
        response = self.client.get("/report/report-001/download/pdf")
        assert b"%PDF-" in response.content

    def test_download_json_content(self) -> None:
        response = self.client.get("/report/report-001/download/json")
        data = response.json()
        assert data["report_id"] == "report-001"

    def test_download_csv_content(self) -> None:
        response = self.client.get("/report/report-001/download/csv")
        assert b"finding_id,title,severity" in response.content

    def test_download_sarif_content(self) -> None:
        response = self.client.get("/report/report-001/download/sarif")
        assert b"2.1.0" in response.content

    def test_download_multiple_formats(self) -> None:
        for fmt in _EXPECTED_FORMATS:
            resp = self.client.get(f"/report/report-001/download/{fmt}")
            assert resp.status_code == 200


# ===========================================================================
# Error handling
# ===========================================================================


class TestDownloadErrors:
    def setup_method(self) -> None:
        self.client = TestClient(_REPORT_APP)

    def test_download_unknown_report(self) -> None:
        response = self.client.get("/report/nonexistent/download/markdown")
        assert response.status_code == 404

    def test_download_unsupported_format(self) -> None:
        response = self.client.get("/report/report-001/download/unknown")
        assert response.status_code == 404

    def test_download_empty_format(self) -> None:
        response = self.client.get("/report/report-001/download/")
        assert response.status_code == 404

    def test_download_without_service(self) -> None:
        client = TestClient(_BASE_APP)
        response = client.get("/report/report-001/download/markdown")
        assert response.status_code == 404


# ===========================================================================
# 405 Method Not Allowed
# ===========================================================================


class TestMethodNotAllowed:
    def setup_method(self) -> None:
        self.client = TestClient(_REPORT_APP)

    def test_post_on_download_markdown(self) -> None:
        response = self.client.post("/report/report-001/download/markdown")
        assert response.status_code == 405

    def test_put_on_download_html(self) -> None:
        response = self.client.put("/report/report-001/download/html")
        assert response.status_code == 405

    def test_delete_on_download_json(self) -> None:
        response = self.client.delete("/report/report-001/download/json")
        assert response.status_code == 405


# ===========================================================================
# OpenAPI schema
# ===========================================================================


class TestOpenAPI:
    def setup_method(self) -> None:
        self.client = TestClient(_REPORT_APP)

    def test_openapi_has_download_path(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        paths = schema["paths"]
        assert "/report/{report_id}/download/{format_name}" in paths

    def test_openapi_download_is_get(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        op = schema["paths"]["/report/{report_id}/download/{format_name}"]
        assert "get" in op

    def test_openapi_download_path_params(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        params = schema["paths"]["/report/{report_id}/download/{format_name}"]["get"]["parameters"]
        param_names = {p["name"] for p in params}
        assert "report_id" in param_names
        assert "format_name" in param_names

    def test_openapi_no_download_without_port(self) -> None:
        client = TestClient(_BASE_APP)
        schema = client.get("/openapi.json").json()
        paths = schema["paths"]
        assert "/report/{report_id}/download/{format_name}" not in paths


# ===========================================================================
# Dependency injection
# ===========================================================================


class TestDependencyInjection:
    def test_create_app_without_port_serves_base(self) -> None:
        client = TestClient(create_app())
        assert client.get("/").status_code == 200

    def test_create_app_with_port_serves_download(self) -> None:
        app = create_app(report_service=_MockReportService(), get_current_user=fake_get_current_user)
        client = TestClient(app)
        assert client.get("/report/report-001/download/markdown").status_code == 200
        assert client.get("/report/report-001/download/html").status_code == 200
        assert client.get("/report/report-001/download/pdf").status_code == 200
        assert client.get("/report/report-001/download/json").status_code == 200
        assert client.get("/report/report-001/download/csv").status_code == 200
        assert client.get("/report/report-001/download/sarif").status_code == 200


# ===========================================================================
# No infrastructure mocking leaks
# ===========================================================================


class TestNoInfrastructureLeaks:
    def test_no_infrastructure_imports_in_routes(self) -> None:
        import inspect

        import kingsec.interfaces.api.routes.download as download_module
        source = inspect.getsource(download_module)
        assert "infrastructure" not in source.lower()

    def test_no_infrastructure_imports_in_app(self) -> None:
        import inspect

        import kingsec.interfaces.api.app as app_module
        source = inspect.getsource(app_module)
        assert "infrastructure" not in source.lower()
