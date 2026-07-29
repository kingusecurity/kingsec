from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application.ports.backup_service import BackupServicePort
from kingsec.domain import Role
from kingsec.domain.backup import (
    BackupId,
    BackupMetadata,
    BackupSchedule,
    BackupSnapshot,
    BackupStatus,
    BackupType,
    BackupVerification,
    DisasterRecoveryPlan,
    RecoveryStatus,
    RecoveryTest,
    ScheduleFrequency,
)


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
            "User", (), {"user_id": "admin", "username": "admin", "role": Role.ADMIN, "claims": None}
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
            "User", (), {"user_id": "viewer", "username": "viewer", "role": Role.VIEWER, "claims": None}
        )()
        resp = app.post("/api/v1/backups", json={"backup_type": "full"})
        assert resp.status_code == 403


class TestRestoreScopeRoutes:
    def test_restore_with_scope(self, app: TestClient, mock_service: MagicMock) -> None:
        op = MagicMock()
        op.restore_id.value = "rest-2"
        op.status.value = "completed"
        op.scope = "database"
        op.dry_run = False
        mock_service.restore_with_scope.return_value = op
        resp = app.post("/api/v1/backups/bkp-1/restore-scope", json={"scope": "database"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["restore_id"] == "rest-2"
        assert "database" in data["message"]

    def test_restore_dry_run(self, app: TestClient, mock_service: MagicMock) -> None:
        op = MagicMock()
        op.restore_id.value = "rest-3"
        op.status.value = "completed"
        op.scope = "complete"
        op.dry_run = True
        mock_service.restore_with_scope.return_value = op
        resp = app.post("/api/v1/backups/bkp-1/restore-scope", json={"dry_run": True})
        assert resp.status_code == 200
        assert resp.json()["dry_run"] is True

    def test_restore_not_found(self, app: TestClient, mock_service: MagicMock) -> None:
        from kingsec.application.errors import BackupNotFoundError
        mock_service.restore_with_scope.side_effect = BackupNotFoundError("not found")
        resp = app.post("/api/v1/backups/bkp-missing/restore-scope", json={})
        assert resp.status_code == 404


class TestVerifyFullRoutes:
    def test_verify_full(self, app: TestClient, mock_service: MagicMock) -> None:
        v = BackupVerification(
            verification_id=BackupId(value="v-1"), backup_id="bkp-1",
            checksum_valid=True, archive_integrity=True, restore_simulation=True,
        )
        mock_service.verify_backup.return_value = v
        resp = app.post("/api/v1/backups/bkp-1/verify-full", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["checksum_valid"] is True
        assert data["archive_integrity"] is True

    def test_verify_not_found(self, app: TestClient, mock_service: MagicMock) -> None:
        from kingsec.application.errors import BackupNotFoundError
        mock_service.verify_backup.side_effect = BackupNotFoundError("not found")
        resp = app.post("/api/v1/backups/bkp-missing/verify-full", json={})
        assert resp.status_code == 404


class TestScheduleRoutes:
    def test_create_schedule(self, app: TestClient, mock_service: MagicMock) -> None:
        sched = BackupSchedule(schedule_id=BackupId(value="s-1"), name="Daily", frequency=ScheduleFrequency.DAILY)
        mock_service.create_schedule.return_value = sched
        resp = app.post("/api/v1/backup-schedules", json={"name": "Daily", "frequency": "daily"})
        assert resp.status_code == 200
        assert resp.json()["schedule"]["name"] == "Daily"

    def test_list_schedules(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.list_schedules.return_value = [
            BackupSchedule(schedule_id=BackupId(value="s-1"), name="A", frequency=ScheduleFrequency.DAILY),
        ]
        resp = app.get("/api/v1/backup-schedules")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_get_schedule_not_found(self, app: TestClient, mock_service: MagicMock) -> None:
        from kingsec.application.errors import ScheduleNotFoundError
        mock_service.get_schedule.side_effect = ScheduleNotFoundError("not found")
        resp = app.get("/api/v1/backup-schedules/s-missing")
        assert resp.status_code in (404, 405)

    def test_update_schedule(self, app: TestClient, mock_service: MagicMock) -> None:
        sched = BackupSchedule(schedule_id=BackupId(value="s-1"), name="New Name", frequency=ScheduleFrequency.DAILY)
        mock_service.update_schedule.return_value = sched
        resp = app.put("/api/v1/backup-schedules/s-1", json={"name": "New Name"})
        assert resp.status_code == 200
        assert resp.json()["schedule"]["name"] == "New Name"

    def test_delete_schedule(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.delete_schedule.return_value = None
        resp = app.delete("/api/v1/backup-schedules/s-1")
        assert resp.status_code == 200

    def test_delete_schedule_not_found(self, app: TestClient, mock_service: MagicMock) -> None:
        from kingsec.application.errors import ScheduleNotFoundError
        mock_service.delete_schedule.side_effect = ScheduleNotFoundError("not found")
        resp = app.delete("/api/v1/backup-schedules/s-missing")
        assert resp.status_code == 404


class TestRecoveryPlanRoutes:
    def test_create_plan(self, app: TestClient, mock_service: MagicMock) -> None:
        plan = DisasterRecoveryPlan(plan_id=BackupId(value="dr-1"), name="DR Plan")
        mock_service.create_recovery_plan.return_value = plan
        resp = app.post("/api/v1/recovery-plans", json={"name": "DR Plan"})
        assert resp.status_code == 200
        assert resp.json()["plan"]["name"] == "DR Plan"

    def test_list_plans(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.list_recovery_plans.return_value = [
            DisasterRecoveryPlan(plan_id=BackupId(value="dr-1"), name="DR"),
        ]
        resp = app.get("/api/v1/recovery-plans")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_get_plan(self, app: TestClient, mock_service: MagicMock) -> None:
        plan = DisasterRecoveryPlan(plan_id=BackupId(value="dr-1"), name="DR")
        mock_service.get_recovery_plan.return_value = plan
        resp = app.get("/api/v1/recovery-plans/dr-1")
        assert resp.status_code == 200
        assert resp.json()["plan"]["name"] == "DR"

    def test_get_plan_not_found(self, app: TestClient, mock_service: MagicMock) -> None:
        from kingsec.application.errors import RecoveryPlanNotFoundError
        mock_service.get_recovery_plan.side_effect = RecoveryPlanNotFoundError("not found")
        resp = app.get("/api/v1/recovery-plans/dr-missing")
        assert resp.status_code == 404

    def test_update_plan(self, app: TestClient, mock_service: MagicMock) -> None:
        plan = DisasterRecoveryPlan(plan_id=BackupId(value="dr-1"), name="Updated DR")
        mock_service.update_recovery_plan.return_value = plan
        resp = app.put("/api/v1/recovery-plans/dr-1", json={"name": "Updated DR"})
        assert resp.status_code == 200
        assert resp.json()["plan"]["name"] == "Updated DR"

    def test_delete_plan(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.delete_recovery_plan.return_value = None
        resp = app.delete("/api/v1/recovery-plans/dr-1")
        assert resp.status_code == 200

    def test_delete_plan_not_found(self, app: TestClient, mock_service: MagicMock) -> None:
        from kingsec.application.errors import RecoveryPlanNotFoundError
        mock_service.delete_recovery_plan.side_effect = RecoveryPlanNotFoundError("not found")
        resp = app.delete("/api/v1/recovery-plans/dr-missing")
        assert resp.status_code == 404


class TestRecoveryTestRoutes:
    def test_test_recovery(self, app: TestClient, mock_service: MagicMock) -> None:
        rt = RecoveryTest(test_id=BackupId(value="rt-1"), plan_id="dr-1", status=RecoveryStatus.COMPLETED, executed_by="admin")
        mock_service.test_recovery.return_value = rt
        resp = app.post("/api/v1/recovery-plans/dr-1/test", json={"executed_by": "admin"})
        assert resp.status_code == 200
        assert resp.json()["test"]["status"] == "completed"

    def test_list_recovery_tests(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.list_recovery_tests.return_value = []
        resp = app.get("/api/v1/recovery-tests")
        assert resp.status_code == 200
        assert resp.json()["tests"] == []

    def test_list_recovery_tests_by_plan(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.list_recovery_tests.return_value = []
        resp = app.get("/api/v1/recovery-tests?plan_id=dr-1")
        assert resp.status_code == 200


class TestHealthReportRoutes:
    def test_health_report(self, app: TestClient, mock_service: MagicMock) -> None:
        report = MagicMock()
        report.overall.value = "healthy"
        report.database_healthy = True
        report.storage_healthy = True
        mock_service.get_health_report.return_value = report
        resp = app.get("/api/v1/backup-health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["overall"] == "healthy"
        assert data["database_healthy"] is True
