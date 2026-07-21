"""FastAPI bootstrap: comprehensive tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from kingsec.interfaces.api.app import create_app


class TestCreateApp:
    def test_create_app_returns_fastapi(self) -> None:
        app = create_app()
        assert app.title == "KingSec API"

    def test_app_version(self) -> None:
        app = create_app()
        from kingsec import __version__

        assert app.version == __version__

    def test_app_description(self) -> None:
        app = create_app()
        assert app.description == "Enterprise Security Assessment Platform"


class TestRootEndpoint:
    def setup_method(self) -> None:
        self.client = TestClient(create_app())

    def test_root_returns_200(self) -> None:
        response = self.client.get("/")
        assert response.status_code == 200

    def test_root_returns_name_and_status(self) -> None:
        response = self.client.get("/")
        data = response.json()
        assert data["name"] == "KingSec"
        assert data["status"] == "running"

    def test_root_content_type(self) -> None:
        response = self.client.get("/")
        assert response.headers["content-type"] == "application/json"


class TestHealthEndpoint:
    def setup_method(self) -> None:
        self.client = TestClient(create_app())

    def test_health_returns_200(self) -> None:
        response = self.client.get("/health")
        assert response.status_code == 200

    def test_health_returns_status(self) -> None:
        response = self.client.get("/health")
        assert response.json() == {"status": "healthy"}


class TestVersionEndpoint:
    def setup_method(self) -> None:
        self.client = TestClient(create_app())

    def test_version_returns_200(self) -> None:
        response = self.client.get("/version")
        assert response.status_code == 200

    def test_version_returns_version(self) -> None:
        response = self.client.get("/version")
        assert isinstance(response.json()["version"], str)


class TestOpenAPI:
    def setup_method(self) -> None:
        self.client = TestClient(create_app())

    def test_openapi_exists(self) -> None:
        response = self.client.get("/openapi.json")
        assert response.status_code == 200

    def test_openapi_title(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        assert schema["info"]["title"] == "KingSec API"

    def test_openapi_version(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        assert isinstance(schema["info"]["version"], str)

    def test_openapi_description(self) -> None:
        response = self.client.get("/openapi.json")
        schema = response.json()
        assert schema["info"]["description"] == "Enterprise Security Assessment Platform"


class TestSwagger:
    def setup_method(self) -> None:
        self.client = TestClient(create_app())

    def test_swagger_ui_exists(self) -> None:
        response = self.client.get("/docs")
        assert response.status_code == 200

    def test_swagger_ui_is_html(self) -> None:
        response = self.client.get("/docs")
        assert "text/html" in response.headers["content-type"]


class TestReDoc:
    def setup_method(self) -> None:
        self.client = TestClient(create_app())

    def test_redoc_exists(self) -> None:
        response = self.client.get("/redoc")
        assert response.status_code == 200

    def test_redoc_is_html(self) -> None:
        response = self.client.get("/redoc")
        assert "text/html" in response.headers["content-type"]


class TestRouting:
    def setup_method(self) -> None:
        self.client = TestClient(create_app())

    def test_unknown_route_returns_404(self) -> None:
        response = self.client.get("/nonexistent")
        assert response.status_code == 404

    def test_method_not_allowed(self) -> None:
        response = self.client.post("/")
        assert response.status_code == 405
