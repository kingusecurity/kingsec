"""Tests for OpenAPI configuration and version routing."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.openapi import configure_openapi
from kingsec.infrastructure.config.models import AppSettings


def _build_app() -> FastAPI:
    app = FastAPI()

    @app.get("/api/v1/test")
    async def test_endpoint():
        return {"ok": True}

    return app


class TestOpenAPI:
    def test_openapi_spec_generated(self) -> None:
        app = _build_app()
        settings = AppSettings()
        configure_openapi(app, settings)
        spec = app.openapi()
        assert spec is not None
        assert "openapi" in spec

    def test_tags_present(self) -> None:
        app = _build_app()
        settings = AppSettings()
        configure_openapi(app, settings)
        spec = app.openapi()
        tag_names = [t["name"] for t in spec.get("tags", [])]
        assert "health" in tag_names
        assert "auth" in tag_names
        assert "assessments" in tag_names
        assert "events" in tag_names

    def test_security_schemes_present(self) -> None:
        app = _build_app()
        settings = AppSettings()
        configure_openapi(app, settings)
        spec = app.openapi()
        assert "bearerAuth" in spec["components"]["securitySchemes"]

    def test_title_and_version(self) -> None:
        app = FastAPI()
        settings = AppSettings(version="1.2.3")
        configure_openapi(app, settings)
        assert app.title == "KingSec API"
        assert app.version == "1.2.3"


class TestVersionRouting:
    def test_v1_routes_accessible(self) -> None:
        from kingsec.adapters.inbound.web.routes import router
        from kingsec.application.ports import UserRepository

        class _StubUserRepository:
            """Phase 3: /health calls app.resolve(UserRepository) directly."""

            def count_by_role(self, role: object) -> int:
                return 1

        class _StubApp:
            def resolve(self, service_type: type) -> object:
                if service_type is UserRepository:
                    return _StubUserRepository()
                raise ValueError(f"unexpected resolve() call in this test: {service_type}")

        app = FastAPI()
        app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]
        app.include_router(router)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_v1_prefix_correct(self) -> None:
        from kingsec.adapters.inbound.web.routes import router

        assert router.prefix == "/api/v1"


class TestAPIDocs:
    def test_docs_endpoint(self) -> None:
        app = FastAPI(docs_url="/docs")

        @app.get("/test")
        async def test_endpoint():
            return {"ok": True}

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/docs")
        assert resp.status_code == 200

    def test_redoc_endpoint(self) -> None:
        app = FastAPI(redoc_url="/redoc")

        @app.get("/test")
        async def test_endpoint():
            return {"ok": True}

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/redoc")
        assert resp.status_code == 200
