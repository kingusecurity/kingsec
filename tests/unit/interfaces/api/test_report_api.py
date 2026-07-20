"""Report API routes: comprehensive tests."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from kingsec.application import ReportGenerationResult, ReportServicePort
from kingsec.application.dto import RenderedReport
from kingsec.application.errors import ReportNotFoundError
from kingsec.interfaces.api.app import create_app

from .helpers import fake_get_current_user

# ---------------------------------------------------------------------------
# Mock port
# ---------------------------------------------------------------------------

_NOW = datetime(2025, 6, 15, 14, 30, 0, tzinfo=timezone.utc)


class _MockReportService(ReportServicePort):
    """Simulates the report service for testing."""

    def __init__(self) -> None:
        self._reports: dict[str, dict] = {
            "report-001": {
                "report_id": "report-001",
                "title": "Security Assessment Report",
                "target": "example.com",
                "generated_at": _NOW.isoformat(),
                "verdict": "High-risk issues found — prompt remediation recommended.",
                "findings": [
                    {
                        "id": "finding-1",
                        "title": "Open SSH port",
                        "severity": "HIGH",
                    },
                ],
                "finding_count": 5,
            },
        }
        self._summaries: dict[str, dict] = {
            "report-001": {
                "executive_summary": {
                    "total_findings": 5,
                    "critical_count": 0,
                    "high_count": 2,
                    "medium_count": 2,
                    "low_count": 1,
                    "overall_risk_level": "HIGH",
                    "summary_text": "Assessment found 5 security issues.",
                },
                "risk_summary": {
                    "average_score": 6.5,
                    "highest_score": 9,
                    "lowest_score": 3,
                    "score_distribution": {
                        "critical": 0,
                        "high": 2,
                        "medium": 2,
                        "low": 1,
                    },
                },
            },
        }
        self._formats: list[str] = ["markdown", "html", "pdf", "json", "csv", "sarif"]
        self._generate_count = 0

    def generate_report(self, scan_id: str) -> ReportGenerationResult:
        self._generate_count += 1
        return ReportGenerationResult(
            report_id=f"report-{scan_id}",
            status="completed",
            generated_at=_NOW,
            finding_count=5,
        )

    def get_report(self, report_id: str) -> dict:
        if report_id not in self._reports:
            raise ReportNotFoundError(f"Report not found: {report_id}")
        return self._reports[report_id]

    def get_summary(self, report_id: str) -> dict:
        if report_id not in self._summaries:
            raise ReportNotFoundError(f"Report not found: {report_id}")
        return self._summaries[report_id]

    def get_formats(self, report_id: str) -> list[str]:
        if report_id not in self._reports:
            raise ReportNotFoundError(f"Report not found: {report_id}")
        return self._formats

    def render_report(self, report_id: str, format_name: str) -> RenderedReport:
        if report_id not in self._reports:
            raise ReportNotFoundError(f"Report not found: {report_id}")
        if format_name not in self._formats:
            raise ValueError(f"Unsupported format: {format_name}")
        content_map = {
            "markdown": (b"# Mock", "text/markdown", ".md"),
            "html": (b"<html></html>", "text/html", ".html"),
            "pdf": (b"%PDF-", "application/pdf", ".pdf"),
            "json": (b"{}", "application/json", ".json"),
            "csv": (b"a,b", "text/csv", ".csv"),
            "sarif": (b"{}", "application/sarif+json", ".sarif"),
        }
        content, media_type, ext = content_map[format_name]
        return RenderedReport(content=content, media_type=media_type, filename=f"report{ext}")


_REPORT_SERVICE = _MockReportService()

_REPORT_APP = create_app(report_service=_REPORT_SERVICE, get_current_user=fake_get_current_user)
_BASE_APP = create_app()


# ===========================================================================
# Report generation (POST /report)
# ===========================================================================


class TestGenerateReport:
    def setup_method(self) -> None:
        self.client = TestClient(_REPORT_APP)

    def test_generate_report_returns_200(self) -> None:
        response = self.client.post("/report", json={"scan_id": "scan-001"})
        assert response.status_code == 200

    def test_generate_report_returns_json(self) -> None:
        response = self.client.post("/report", json={"scan_id": "scan-001"})
        data = response.json()
        assert "report_id" in data
        assert data["status"] == "completed"
        assert "generated_at" in data
        assert "finding_count" in data

    def test_generate_report_finding_count(self) -> None:
        response = self.client.post("/report", json={"scan_id": "scan-001"})
        data = response.json()
        assert data["finding_count"] == 5

    def test_generate_report_id(self) -> None:
        response = self.client.post("/report", json={"scan_id": "scan-001"})
        data = response.json()
        assert data["report_id"] == "report-scan-001"

    def test_generate_report_generated_at(self) -> None:
        response = self.client.post("/report", json={"scan_id": "scan-001"})
        data = response.json()
        from datetime import datetime
        datetime.fromisoformat(data["generated_at"])

    def test_generate_multiple_reports(self) -> None:
        self.client.post("/report", json={"scan_id": "a"})
        self.client.post("/report", json={"scan_id": "b"})
        self.client.post("/report", json={"scan_id": "c"})
        response = self.client.post("/report", json={"scan_id": "d"})
        assert response.status_code == 200


# ===========================================================================
# Validation errors — scan_id
# ===========================================================================


class TestValidationScanId:
    def setup_method(self) -> None:
        self.client = TestClient(_REPORT_APP)

    def test_empty_scan_id(self) -> None:
        response = self.client.post("/report", json={"scan_id": ""})
        assert response.status_code == 422

    def test_missing_scan_id(self) -> None:
        response = self.client.post("/report", json={})
        assert response.status_code == 422

    def test_whitespace_scan_id(self) -> None:
        response = self.client.post("/report", json={"scan_id": "   "})
        assert response.status_code == 422

    def test_scan_id_not_string(self) -> None:
        response = self.client.post("/report", json={"scan_id": 123})
        assert response.status_code == 422

    def test_null_scan_id(self) -> None:
        response = self.client.post("/report", json={"scan_id": None})
        assert response.status_code == 422


# ===========================================================================
# Report retrieval (GET /report/{report_id})
# ===========================================================================


class TestGetReport:
    def setup_method(self) -> None:
        self.client = TestClient(_REPORT_APP)

    def test_get_report_returns_200(self) -> None:
        response = self.client.get("/report/report-001")
        assert response.status_code == 200

    def test_get_report_returns_json(self) -> None:
        response = self.client.get("/report/report-001")
        data = response.json()
        assert data["report_id"] == "report-001"
        assert data["title"] == "Security Assessment Report"

    def test_get_report_unknown_id(self) -> None:
        response = self.client.get("/report/nonexistent")
        assert response.status_code == 404

    def test_get_report_empty_id(self) -> None:
        response = self.client.get("/report/ ")
        assert response.status_code == 422


# ===========================================================================
# Report summary (GET /report/{report_id}/summary)
# ===========================================================================


class TestGetSummary:
    def setup_method(self) -> None:
        self.client = TestClient(_REPORT_APP)

    def test_get_summary_returns_200(self) -> None:
        response = self.client.get("/report/report-001/summary")
        assert response.status_code == 200

    def test_get_summary_returns_json(self) -> None:
        response = self.client.get("/report/report-001/summary")
        data = response.json()
        assert "executive_summary" in data
        assert "risk_summary" in data

    def test_get_summary_executive_summary_fields(self) -> None:
        response = self.client.get("/report/report-001/summary")
        es = response.json()["executive_summary"]
        assert es["total_findings"] == 5
        assert es["overall_risk_level"] == "HIGH"

    def test_get_summary_risk_summary_fields(self) -> None:
        response = self.client.get("/report/report-001/summary")
        rs = response.json()["risk_summary"]
        assert rs["average_score"] == 6.5
        assert rs["highest_score"] == 9

    def test_get_summary_unknown_id(self) -> None:
        response = self.client.get("/report/nonexistent/summary")
        assert response.status_code == 404


# ===========================================================================
# Report formats (GET /report/{report_id}/formats)
# ===========================================================================


class TestGetFormats:
    def setup_method(self) -> None:
        self.client = TestClient(_REPORT_APP)

    def test_get_formats_returns_200(self) -> None:
        response = self.client.get("/report/report-001/formats")
        assert response.status_code == 200

    def test_get_formats_returns_list(self) -> None:
        response = self.client.get("/report/report-001/formats")
        data = response.json()
        assert isinstance(data, list)

    def test_get_formats_contains_expected(self) -> None:
        response = self.client.get("/report/report-001/formats")
        formats = response.json()
        assert "markdown" in formats
        assert "html" in formats
        assert "pdf" in formats
        assert "json" in formats
        assert "csv" in formats
        assert "sarif" in formats

    def test_get_formats_count(self) -> None:
        response = self.client.get("/report/report-001/formats")
        assert len(response.json()) == 6

    def test_get_formats_unknown_id(self) -> None:
        response = self.client.get("/report/nonexistent/formats")
        assert response.status_code == 404


# ===========================================================================
# 404 Not Found
# ===========================================================================


class TestNotFound:
    def setup_method(self) -> None:
        self.client = TestClient(_REPORT_APP)

    def test_unknown_report_route(self) -> None:
        response = self.client.get("/report/foo/bar")
        assert response.status_code == 404

    def test_unknown_summary_route(self) -> None:
        response = self.client.get("/report/report-001/unknown")
        assert response.status_code == 404

    def test_no_report_routes_without_service(self) -> None:
        client = TestClient(_BASE_APP)
        response = client.get("/report/report-001")
        assert response.status_code == 404


# ===========================================================================
# 405 Method Not Allowed
# ===========================================================================


class TestMethodNotAllowed:
    def setup_method(self) -> None:
        self.client = TestClient(_REPORT_APP)

    def test_get_on_report(self) -> None:
        response = self.client.get("/report")
        assert response.status_code == 405

    def test_put_on_report(self) -> None:
        response = self.client.put("/report", json={"scan_id": "x"})
        assert response.status_code == 405

    def test_delete_on_report(self) -> None:
        response = self.client.delete("/report")
        assert response.status_code == 405

    def test_put_on_report_id(self) -> None:
        response = self.client.put("/report/report-001")
        assert response.status_code == 405

    def test_delete_on_report_id(self) -> None:
        response = self.client.delete("/report/report-001")
        assert response.status_code == 405

    def test_post_on_report_id(self) -> None:
        response = self.client.post("/report/report-001")
        assert response.status_code == 405

    def test_put_on_summary(self) -> None:
        response = self.client.put("/report/report-001/summary")
        assert response.status_code == 405

    def test_delete_on_formats(self) -> None:
        response = self.client.delete("/report/report-001/formats")
        assert response.status_code == 405


# ===========================================================================
# OpenAPI schema
# ===========================================================================


class TestOpenAPI:
    def setup_method(self) -> None:
        self.client = TestClient(_REPORT_APP)

    def test_openapi_has_report_paths(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        paths = schema["paths"]
        assert "/report" in paths
        assert "/report/{report_id}" in paths
        assert "/report/{report_id}/summary" in paths
        assert "/report/{report_id}/formats" in paths

    def test_openapi_report_post(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        assert "post" in schema["paths"]["/report"]

    def test_openapi_report_get(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        assert "get" in schema["paths"]["/report/{report_id}"]

    def test_openapi_summary_get(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        assert "get" in schema["paths"]["/report/{report_id}/summary"]

    def test_openapi_formats_get(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        assert "get" in schema["paths"]["/report/{report_id}/formats"]

    def test_openapi_has_report_tag(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        assert schema["paths"]["/report"]["post"]["tags"] == ["report"]

    def test_openapi_no_report_without_port(self) -> None:
        client = TestClient(_BASE_APP)
        response = client.get("/openapi.json")
        paths = response.json()["paths"]
        assert "/report" not in paths


# ===========================================================================
# Dependency injection
# ===========================================================================


class TestDependencyInjection:
    def test_create_app_without_port_still_works(self) -> None:
        app = create_app()
        assert app.title == "KingSec API"

    def test_create_app_without_port_serves_base(self) -> None:
        client = TestClient(create_app())
        assert client.get("/").status_code == 200
        assert client.get("/health").status_code == 200
        assert client.get("/version").status_code == 200

    def test_create_app_with_port_serves_report(self) -> None:
        app = create_app(report_service=_MockReportService(), get_current_user=fake_get_current_user)
        client = TestClient(app)
        assert client.post("/report", json={"scan_id": "x"}).status_code == 200
        assert client.get("/report/report-001").status_code == 200
        assert client.get("/report/report-001/summary").status_code == 200
        assert client.get("/report/report-001/formats").status_code == 200


# ===========================================================================
# No infrastructure mocking leaks
# ===========================================================================


class TestNoInfrastructureLeaks:
    def test_no_infrastructure_imports_in_routes(self) -> None:
        import kingsec.interfaces.api.routes.report as report_module
        import inspect
        source = inspect.getsource(report_module)
        assert "infrastructure" not in source.lower()

    def test_no_infrastructure_imports_in_app(self) -> None:
        import kingsec.interfaces.api.app as app_module
        import inspect
        source = inspect.getsource(app_module)
        assert "infrastructure" not in source.lower()
