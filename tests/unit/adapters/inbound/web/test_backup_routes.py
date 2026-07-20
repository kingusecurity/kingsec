from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application.ports.backup_service import BackupServicePort
from kingsec.domain import Role
from kingsec.domain.backup import BackupId, BackupMetadata, BackupSnapshot, BackupStatus, BackupType


@pytest.fixture
def mock_service() -> MagicMock:
    return MagicMock(spec=BackupServicePort)


@pytest.fixture
def app(mock_service: MagicMock) -> TestClient:
    with patch("kingsec.bootstrap.application.Application") as MockApp:
        app_instance = MockApp()
        app_instance.resolve.return_value = mock_service

        app = FastAPI()
        from kingsec.adapters.inbound.web.backup_routes import router
        app.include_router(router)
        app.state.kingsec_app = app_instance

        from kingsec.adapters.inbound.web.auth import get_current_user
        app.dependency_overrides[get_current_user] = lambda: type(
            "User", (), {"user_id": "admin", "username": "admin",
                         "role": Role.ADMIN, "claims": None}
        )()
        return TestClient(app)


def _make_backup(bid: str = "bkp-1", status: str = "completed") -> BackupMetadata:
    return BackupMetadata(
        backup_id=BackupId(value=bid),
        backup_type=BackupType.FULL,
        status=BackupStatus(status),
        size_bytes=1024,
        encrypted=True,
        compressed=True,
    )


class TestBackupRoutes:
    def test_create_backup(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.create_backup.return_value = _make_backup()
        resp = app.post("/api/v1/backups", json={"backup_type": "full"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["backup"]["backup_id"] == "bkp-1"
        assert data["backup"]["backup_type"] == "full"

    def test_list_backups(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.list_backups.return_value = [_make_backup(), _make_backup("bkp-2")]
        resp = app.get("/api/v1/backups")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2

    def test_get_backup(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.list_backups.return_value = [_make_backup("bkp-1")]
        resp = app.get("/api/v1/backups/bkp-1")
        assert resp.status_code == 200
        assert resp.json()["backup_id"] == "bkp-1"

    def test_get_backup_not_found(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.list_backups.return_value = []
        resp = app.get("/api/v1/backups/bkp-missing")
        assert resp.status_code == 404

    def test_delete_backup(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.delete_backup.return_value = None
        resp = app.delete("/api/v1/backups/bkp-1")
        assert resp.status_code == 200
        assert "deleted" in resp.json()["message"]

    def test_delete_backup_not_found(self, app: TestClient, mock_service: MagicMock) -> None:
        from kingsec.application.errors import BackupNotFoundError
        mock_service.delete_backup.side_effect = BackupNotFoundError("not found")
        resp = app.delete("/api/v1/backups/bkp-missing")
        assert resp.status_code == 404

    def test_restore_backup(self, app: TestClient, mock_service: MagicMock) -> None:
        op = MagicMock()
        op.restore_id.value = "rest-1"
        op.status.value = "completed"
        mock_service.restore_backup.return_value = op
        resp = app.post("/api/v1/backups/bkp-1/restore", json={})
        assert resp.status_code == 200
        assert resp.json()["restore_id"] == "rest-1"

    def test_verify_backup(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.validate_backup.return_value = True
        resp = app.post("/api/v1/backups/bkp-1/verify", json={})
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_cleanup_backups(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.cleanup_expired.return_value = 3
        resp = app.post("/api/v1/backups/cleanup", json={})
        assert resp.status_code == 200
        assert resp.json()["deleted"] == 3

    def test_create_snapshot(self, app: TestClient, mock_service: MagicMock) -> None:
        snap = BackupSnapshot(snapshot_id=BackupId(value="snap-1"), label="weekly")
        mock_service.create_snapshot.return_value = snap
        resp = app.post("/api/v1/snapshots", json={"label": "weekly", "backup_ids": ["bkp-1"]})
        assert resp.status_code == 200
        data = resp.json()
        assert data["snapshot"]["snapshot_id"] == "snap-1"

    def test_list_snapshots(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.list_snapshots.return_value = [
            BackupSnapshot(snapshot_id=BackupId(value="snap-1")),
        ]
        resp = app.get("/api/v1/snapshots")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1

    def test_restore_snapshot(self, app: TestClient, mock_service: MagicMock) -> None:
        op = MagicMock()
        op.restore_id.value = "rest-1"
        op.status.value = "completed"
        mock_service.restore_snapshot.return_value = op
        resp = app.post("/api/v1/snapshots/snap-1/restore", json={})
        assert resp.status_code == 200

    def test_unauthorized_without_admin(self, app: TestClient, mock_service: MagicMock) -> None:
        from kingsec.adapters.inbound.web.auth import get_current_user
        app.app.dependency_overrides[get_current_user] = lambda: type(
            "User", (), {"user_id": "viewer", "username": "viewer",
                         "role": Role.VIEWER, "claims": None}
        )()
        resp = app.post("/api/v1/backups", json={"backup_type": "full"})
        assert resp.status_code == 403
