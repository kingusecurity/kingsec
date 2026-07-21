"""Scan API routes: comprehensive tests."""

from __future__ import annotations

from collections.abc import Sequence

from fastapi.testclient import TestClient

from kingsec.application.errors import ScannerPluginError
from kingsec.application.ports import ScannerPluginRegistry, ScannerPort
from kingsec.domain import (
    Finding,
    PluginAvailability,
    ScannerId,
    ScannerPluginMetadata,
    Severity,
    Target,
)
from kingsec.interfaces.api.app import create_app

from .helpers import fake_get_current_user

# ---------------------------------------------------------------------------
# Mock ports
# ---------------------------------------------------------------------------


class _MockRegistry(ScannerPluginRegistry):
    def __init__(self) -> None:
        self._plugins: dict[str, object] = {
            "nuclei": object(),
            "nmap": object(),
            "nikto": object(),
        }

    def register(self, plugin: object) -> None:
        pass

    def get(self, plugin_id: ScannerId) -> object:
        if plugin_id.value in self._plugins:
            return self._plugins[plugin_id.value]
        raise ScannerPluginError(f"Unknown scanner: {plugin_id.value}")

    def resolve(self, target: Target) -> tuple[object, ...]:
        return tuple(self._plugins.values())

    def list_all(self) -> tuple[tuple[ScannerPluginMetadata, PluginAvailability], ...]:
        return (
            (
                ScannerPluginMetadata(
                    id=ScannerId("nuclei"),
                    name="Nuclei",
                    version="1.0.0",
                    author="KingSec",
                    description="Fast vulnerability scanner",
                    api_version="1.0",
                ),
                PluginAvailability(available=True),
            ),
            (
                ScannerPluginMetadata(
                    id=ScannerId("nmap"),
                    name="Nmap",
                    version="7.95.0",
                    author="KingSec",
                    description="Network discovery scanner",
                    api_version="1.0",
                ),
                PluginAvailability(available=True),
            ),
            (
                ScannerPluginMetadata(
                    id=ScannerId("nikto"),
                    name="Nikto",
                    version="2.5.0",
                    author="KingSec",
                    description="Web server scanner",
                    api_version="1.0",
                ),
                PluginAvailability(available=False, reason="not installed"),
            ),
        )


class _MockScanner(ScannerPort):
    def scan(self, target: Target) -> Sequence[Finding]:
        return (
            Finding.create(
                title="Open SSH port",
                description="SSH port 22 is open",
                severity=Severity.HIGH,
            ),
            Finding.create(
                title="HTTP exposed",
                description="HTTP service detected",
                severity=Severity.MEDIUM,
            ),
        )


_REGISTRY = _MockRegistry()
_SCANNER = _MockScanner()

# App with scan routes wired
_SCAN_APP = create_app(registry=_REGISTRY, scanner=_SCANNER, get_current_user=fake_get_current_user)
# App without scan routes (base only)
_BASE_APP = create_app()


# ===========================================================================
# Successful scan
# ===========================================================================


class TestSuccessfulScan:
    def setup_method(self) -> None:
        self.client = TestClient(_SCAN_APP)

    def test_scan_returns_200(self) -> None:
        response = self.client.post("/scan", json={"target": "example.com"})
        assert response.status_code == 200

    def test_scan_returns_json(self) -> None:
        response = self.client.post("/scan", json={"target": "example.com"})
        data = response.json()
        assert "scan_id" in data
        assert data["status"] == "completed"
        assert isinstance(data["findings"], int)
        assert isinstance(data["scanner_count"], int)

    def test_scan_findings_count(self) -> None:
        response = self.client.post("/scan", json={"target": "example.com"})
        data = response.json()
        assert data["findings"] == 2

    def test_scan_scanner_count(self) -> None:
        response = self.client.post("/scan", json={"target": "example.com"})
        data = response.json()
        assert data["scanner_count"] == 3

    def test_scan_id_is_uuid(self) -> None:
        response = self.client.post("/scan", json={"target": "example.com"})
        data = response.json()
        import uuid
        uuid.UUID(data["scan_id"])

    def test_scan_with_ip_target(self) -> None:
        response = self.client.post("/scan", json={"target": "10.0.0.1"})
        assert response.status_code == 200
        assert response.json()["status"] == "completed"

    def test_scan_with_url_target(self) -> None:
        response = self.client.post("/scan", json={"target": "https://example.com"})
        assert response.status_code == 200
        assert response.json()["status"] == "completed"


# ===========================================================================
# Custom scan
# ===========================================================================


class TestCustomScan:
    def setup_method(self) -> None:
        self.client = TestClient(_SCAN_APP)

    def test_custom_scan_returns_200(self) -> None:
        response = self.client.post(
            "/scan/custom",
            json={"target": "example.com", "scanners": ["nuclei"]},
        )
        assert response.status_code == 200

    def test_custom_scan_returns_json(self) -> None:
        response = self.client.post(
            "/scan/custom",
            json={"target": "example.com", "scanners": ["nuclei"]},
        )
        data = response.json()
        assert data["status"] == "completed"
        assert data["scanner_count"] == 1

    def test_custom_scan_multiple_scanners(self) -> None:
        response = self.client.post(
            "/scan/custom",
            json={"target": "example.com", "scanners": ["nuclei", "nmap"]},
        )
        assert response.status_code == 200
        assert response.json()["scanner_count"] == 2


# ===========================================================================
# Validation errors — target
# ===========================================================================


class TestValidationTarget:
    def setup_method(self) -> None:
        self.client = TestClient(_SCAN_APP)

    def test_empty_target(self) -> None:
        response = self.client.post("/scan", json={"target": ""})
        assert response.status_code == 422

    def test_missing_target(self) -> None:
        response = self.client.post("/scan", json={})
        assert response.status_code == 422

    def test_whitespace_target(self) -> None:
        response = self.client.post("/scan", json={"target": "   "})
        assert response.status_code == 422

    def test_target_not_string(self) -> None:
        response = self.client.post("/scan", json={"target": 123})
        assert response.status_code == 422

    def test_null_target(self) -> None:
        response = self.client.post("/scan", json={"target": None})
        assert response.status_code == 422

    def test_empty_target_custom_scan(self) -> None:
        response = self.client.post(
            "/scan/custom",
            json={"target": "", "scanners": ["nuclei"]},
        )
        assert response.status_code == 422

    def test_missing_target_custom_scan(self) -> None:
        response = self.client.post(
            "/scan/custom",
            json={"scanners": ["nuclei"]},
        )
        assert response.status_code == 422


# ===========================================================================
# Validation errors — scanners
# ===========================================================================


class TestValidationScanners:
    def setup_method(self) -> None:
        self.client = TestClient(_SCAN_APP)

    def test_invalid_scanner_id(self) -> None:
        response = self.client.post(
            "/scan/custom",
            json={"target": "example.com", "scanners": ["nonexistent"]},
        )
        assert response.status_code == 422

    def test_missing_scanners_field(self) -> None:
        response = self.client.post(
            "/scan/custom",
            json={"target": "example.com"},
        )
        assert response.status_code == 422

    def test_empty_scanners_list(self) -> None:
        response = self.client.post(
            "/scan/custom",
            json={"target": "example.com", "scanners": []},
        )
        assert response.status_code == 422

    def test_scanners_not_a_list(self) -> None:
        response = self.client.post(
            "/scan/custom",
            json={"target": "example.com", "scanners": "nuclei"},
        )
        assert response.status_code == 422

    def test_duplicate_scanner_ids(self) -> None:
        response = self.client.post(
            "/scan/custom",
            json={"target": "example.com", "scanners": ["nuclei", "nuclei"]},
        )
        assert response.status_code == 422

    def test_partially_invalid_scanners(self) -> None:
        response = self.client.post(
            "/scan/custom",
            json={"target": "example.com", "scanners": ["nuclei", "bogus"]},
        )
        assert response.status_code == 422


# ===========================================================================
# 404 Not Found
# ===========================================================================


class TestNotFound:
    def setup_method(self) -> None:
        self.client = TestClient(_SCAN_APP)

    def test_unknown_scan_route(self) -> None:
        response = self.client.get("/scan/unknown")
        assert response.status_code == 404

    def test_unknown_custom_route(self) -> None:
        response = self.client.get("/scan/custom/extra")
        assert response.status_code == 404


# ===========================================================================
# 405 Method Not Allowed
# ===========================================================================


class TestMethodNotAllowed:
    def setup_method(self) -> None:
        self.client = TestClient(_SCAN_APP)

    def test_get_on_scan(self) -> None:
        response = self.client.get("/scan")
        assert response.status_code == 405

    def test_put_on_scan(self) -> None:
        response = self.client.put("/scan", json={"target": "example.com"})
        assert response.status_code == 405

    def test_delete_on_scan(self) -> None:
        response = self.client.delete("/scan")
        assert response.status_code == 405

    def test_get_on_custom_scan(self) -> None:
        response = self.client.get("/scan/custom")
        assert response.status_code == 405


# ===========================================================================
# Scanner listing
# ===========================================================================


class TestScannerListing:
    def setup_method(self) -> None:
        self.client = TestClient(_SCAN_APP)

    def test_list_scanners_returns_200(self) -> None:
        response = self.client.get("/scan/scanners")
        assert response.status_code == 200

    def test_list_scanners_returns_list(self) -> None:
        response = self.client.get("/scan/scanners")
        data = response.json()
        assert isinstance(data, list)

    def test_list_scanners_contains_all(self) -> None:
        response = self.client.get("/scan/scanners")
        ids = [s["id"] for s in response.json()]
        assert "nuclei" in ids
        assert "nmap" in ids
        assert "nikto" in ids

    def test_list_scanners_metadata_fields(self) -> None:
        response = self.client.get("/scan/scanners")
        nuclei = next(s for s in response.json() if s["id"] == "nuclei")
        assert nuclei["name"] == "Nuclei"
        assert nuclei["version"] == "1.0.0"

    def test_list_scanners_no_scan_routes(self) -> None:
        """Without scanner ports, the /scan routes should not exist."""
        client = TestClient(_BASE_APP)
        response = client.get("/scan/scanners")
        assert response.status_code == 404


# ===========================================================================
# OpenAPI schema
# ===========================================================================


class TestOpenAPI:
    def setup_method(self) -> None:
        self.client = TestClient(_SCAN_APP)

    def test_openapi_has_scan_paths(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        paths = schema["paths"]
        assert "/scan" in paths
        assert "/scan/custom" in paths
        assert "/scan/scanners" in paths

    def test_openapi_scan_post(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        assert "post" in schema["paths"]["/scan"]

    def test_openapi_custom_scan_post(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        assert "post" in schema["paths"]["/scan/custom"]

    def test_openapi_scanners_get(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        assert "get" in schema["paths"]["/scan/scanners"]

    def test_openapi_has_scan_tag(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        assert schema["paths"]["/scan"]["post"]["tags"] == ["scan"]

    def test_openapi_no_scan_routes_without_ports(self) -> None:
        client = TestClient(_BASE_APP)
        response = client.get("/openapi.json")
        paths = response.json()["paths"]
        assert "/scan" not in paths


# ===========================================================================
# Dependency injection
# ===========================================================================


class TestDependencyInjection:
    def test_create_app_without_ports_still_works(self) -> None:
        """create_app() should work without any port arguments."""
        app = create_app()
        assert app.title == "KingSec API"

    def test_create_app_without_ports_serves_base_endpoints(self) -> None:
        client = TestClient(create_app())
        assert client.get("/").status_code == 200
        assert client.get("/health").status_code == 200
        assert client.get("/version").status_code == 200

    def test_create_app_with_ports_serves_scan_endpoints(self) -> None:
        app = create_app(registry=_REGISTRY, scanner=_SCANNER, get_current_user=fake_get_current_user)
        client = TestClient(app)
        assert client.post("/scan", json={"target": "x"}).status_code == 200
        assert client.get("/scan/scanners").status_code == 200


# ===========================================================================
# No infrastructure mocking leaks
# ===========================================================================


class TestNoInfrastructureLeaks:
    def test_no_infrastructure_imports_in_routes(self) -> None:
        """The scan route module should not import infrastructure packages."""
        import inspect

        import kingsec.interfaces.api.routes.scan as scan_module
        source = inspect.getsource(scan_module)
        assert "infrastructure" not in source.lower()

    def test_no_infrastructure_imports_in_app(self) -> None:
        """The app module should not import infrastructure packages."""
        import inspect

        import kingsec.interfaces.api.app as app_module
        source = inspect.getsource(app_module)
        assert "infrastructure" not in source.lower()
