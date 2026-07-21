from __future__ import annotations

import io
import json
import zipfile
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from kingsec.application.ports.plugin_service import PluginServicePort
from kingsec.domain.plugin_package import (
    PluginHealth,
    PluginInstallStatus,
    PluginManifest,
    PluginPackage,
    PluginVersion,
)


@pytest.fixture
def mock_service() -> MagicMock:
    service = MagicMock(spec=PluginServicePort)
    service.list_plugins.return_value = []
    service.get_plugin.return_value = None
    service.install.return_value = PluginPackage(
        id="test-plugin",
        manifest=PluginManifest(id="test-plugin", name="Test Plugin", version=PluginVersion(1, 0, 0)),
        status=PluginInstallStatus.INSTALLED,
        health=PluginHealth.HEALTHY,
    )
    service.uninstall.return_value = None
    service.enable.return_value = PluginPackage(
        id="test-plugin",
        manifest=PluginManifest(id="test-plugin", name="Test Plugin", version=PluginVersion(1, 0, 0)),
        status=PluginInstallStatus.ENABLED,
        health=PluginHealth.HEALTHY,
    )
    service.disable.return_value = PluginPackage(
        id="test-plugin",
        manifest=PluginManifest(id="test-plugin", name="Test Plugin", version=PluginVersion(1, 0, 0)),
        status=PluginInstallStatus.DISABLED,
        health=PluginHealth.HEALTHY,
    )
    service.update.return_value = PluginPackage(
        id="test-plugin",
        manifest=PluginManifest(id="test-plugin", name="Test Plugin", version=PluginVersion(2, 0, 0)),
        status=PluginInstallStatus.INSTALLED,
        health=PluginHealth.HEALTHY,
    )
    service.rollback.return_value = PluginPackage(
        id="test-plugin",
        manifest=PluginManifest(id="test-plugin", name="Test Plugin", version=PluginVersion(1, 0, 0)),
        status=PluginInstallStatus.ROLLED_BACK,
        health=PluginHealth.HEALTHY,
    )
    service.validate.return_value = {"valid": True, "manifest": {"id": "test-plugin"}, "errors": []}
    service.check_updates.return_value = []
    service.import_plugin.return_value = PluginPackage(
        id="test-plugin",
        manifest=PluginManifest(id="test-plugin", name="Test Plugin", version=PluginVersion(1, 0, 0)),
        status=PluginInstallStatus.INSTALLED,
        health=PluginHealth.HEALTHY,
    )
    service.export_plugin.side_effect = lambda pid: None if pid == "nonexistent" else b"zipdata"
    return service


@pytest.fixture
def app(mock_service: MagicMock) -> TestClient:
    with patch("kingsec.bootstrap.application.Application") as MockApp:
        app_instance = MockApp()
        app_instance.resolve.return_value = mock_service

        from fastapi import FastAPI

        app = FastAPI()
        from kingsec.adapters.inbound.web.plugin_routes import router

        app.include_router(router)
        app.state.kingsec_app = app_instance
        client = TestClient(app)
        from kingsec.adapters.inbound.web.auth import get_current_user
        from kingsec.domain import Role

        app.dependency_overrides[get_current_user] = lambda: type(
            "User", (), {"id": "admin", "username": "admin", "role": Role.ADMIN, "claims": None}
        )()
        return client


def _create_plugin_zip(version: str = "1.0.0") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "manifest.json",
            json.dumps(
                {
                    "id": "test-plugin",
                    "name": "Test Plugin",
                    "version": version,
                    "author": "KingSec",
                    "license": "MIT",
                    "description": "",
                }
            ),
        )
        zf.writestr("main.py", "print('hello')")
    buf.seek(0)
    return buf.getvalue()


class TestPluginRoutes:
    def test_list_plugins_empty(self, app: TestClient) -> None:
        resp = app.get("/api/v1/plugins")
        assert resp.status_code == 200
        assert resp.json()["plugins"] == []

    def test_list_plugins_with_data(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.list_plugins.return_value = [
            PluginPackage(
                id="test-plugin",
                manifest=PluginManifest(id="test-plugin", name="Test Plugin", version=PluginVersion(1, 0, 0)),
                status=PluginInstallStatus.INSTALLED,
                health=PluginHealth.HEALTHY,
            )
        ]
        resp = app.get("/api/v1/plugins")
        assert resp.status_code == 200
        assert len(resp.json()["plugins"]) == 1

    def test_get_plugin_found(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.get_plugin.return_value = PluginPackage(
            id="test-plugin",
            manifest=PluginManifest(id="test-plugin", name="Test Plugin", version=PluginVersion(1, 0, 0)),
            status=PluginInstallStatus.INSTALLED,
            health=PluginHealth.HEALTHY,
        )
        resp = app.get("/api/v1/plugins/test-plugin")
        assert resp.status_code == 200
        assert resp.json()["id"] == "test-plugin"

    def test_get_plugin_not_found(self, app: TestClient) -> None:
        resp = app.get("/api/v1/plugins/nonexistent")
        assert resp.status_code == 404

    def test_install_plugin(self, app: TestClient) -> None:
        resp = app.post(
            "/api/v1/plugins/install", files={"file": ("test.zip", _create_plugin_zip(), "application/zip")}
        )
        assert resp.status_code == 200
        assert resp.json()["plugin"]["id"] == "test-plugin"

    def test_install_plugin_no_file(self, app: TestClient) -> None:
        resp = app.post("/api/v1/plugins/install")
        assert resp.status_code == 422

    def test_uninstall_plugin(self, app: TestClient) -> None:
        resp = app.post("/api/v1/plugins/uninstall", params={"plugin_id": "test-plugin"})
        assert resp.status_code == 200

    def test_enable_plugin(self, app: TestClient) -> None:
        resp = app.post("/api/v1/plugins/enable", params={"plugin_id": "test-plugin"})
        assert resp.status_code == 200
        assert resp.json()["plugin"]["status"] == "enabled"

    def test_disable_plugin(self, app: TestClient) -> None:
        resp = app.post("/api/v1/plugins/disable", params={"plugin_id": "test-plugin"})
        assert resp.status_code == 200
        assert resp.json()["plugin"]["status"] == "disabled"

    def test_update_plugin(self, app: TestClient) -> None:
        resp = app.post(
            "/api/v1/plugins/update",
            params={"plugin_id": "test-plugin"},
            files={"file": ("test.zip", _create_plugin_zip(version="2.0.0"), "application/zip")},
        )
        assert resp.status_code == 200

    def test_rollback_plugin(self, app: TestClient) -> None:
        resp = app.post("/api/v1/plugins/rollback", params={"plugin_id": "test-plugin"})
        assert resp.status_code == 200

    def test_validate_plugin(self, app: TestClient) -> None:
        resp = app.post(
            "/api/v1/plugins/validate", files={"file": ("test.zip", _create_plugin_zip(), "application/zip")}
        )
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_check_updates(self, app: TestClient) -> None:
        resp = app.get("/api/v1/plugins/updates", params={"plugin_id": "test-plugin"})
        assert resp.status_code == 200

    def test_import_plugin(self, app: TestClient) -> None:
        resp = app.post("/api/v1/plugins/import", files={"file": ("test.zip", _create_plugin_zip(), "application/zip")})
        assert resp.status_code == 200

    def test_export_plugin_found(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.export_plugin.side_effect = None
        mock_service.export_plugin.return_value = b"zipdata"
        resp = app.get("/api/v1/plugins/export/test-plugin")
        assert resp.status_code == 200
        assert "data" in resp.json()

    def test_export_plugin_not_found(self, app: TestClient) -> None:
        resp = app.get("/api/v1/plugins/export/nonexistent")
        assert resp.status_code == 404
