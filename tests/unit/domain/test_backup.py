from __future__ import annotations

from kingsec.domain.backup import (
    BackupId,
    BackupMetadata,
    BackupSchedule,
    BackupSnapshot,
    BackupStatus,
    BackupType,
    BackupVerification,
    ComponentHealth,
    ComponentHealthStatus,
    CompressionFormat,
    DisasterRecoveryPlan,
    HealthReport,
    RecoveryChecklistItem,
    RecoveryStatus,
    RecoveryTest,
    RestoreOperation,
    RestoreScope,
    RetentionPolicy,
    ScheduleFrequency,
)


class TestBackupId:
    def test_value(self) -> None:
        bid = BackupId(value="bkp-1")
        assert bid.value == "bkp-1"
        assert str(bid) == "bkp-1"


class TestBackupType:
    def test_values(self) -> None:
        assert BackupType.FULL.value == "full"
        assert BackupType.INCREMENTAL.value == "incremental"
        assert BackupType.DIFFERENTIAL.value == "differential"
        assert BackupType.SNAPSHOT.value == "snapshot"


class TestBackupStatus:
    def test_values(self) -> None:
        assert BackupStatus.PENDING.value == "pending"
        assert BackupStatus.RUNNING.value == "running"
        assert BackupStatus.COMPLETED.value == "completed"
        assert BackupStatus.FAILED.value == "failed"
        assert BackupStatus.RESTORING.value == "restoring"
        assert BackupStatus.CANCELLED.value == "cancelled"


class TestBackupMetadata:
    def test_defaults(self) -> None:
        bid = BackupId(value="bkp-1")
        bm = BackupMetadata(backup_id=bid, backup_type=BackupType.FULL, status=BackupStatus.PENDING)
        assert bm.backup_id.value == "bkp-1"
        assert bm.size_bytes == 0
        assert bm.encrypted is False

    def test_full_construction(self) -> None:
        bid = BackupId(value="bkp-2")
        bm = BackupMetadata(
            backup_id=bid,
            backup_type=BackupType.INCREMENTAL,
            status=BackupStatus.COMPLETED,
            size_bytes=1024,
            checksum="abc123",
            encrypted=True,
            compressed=True,
        )
        assert bm.backup_type == BackupType.INCREMENTAL
        assert bm.checksum == "abc123"


class TestBackupSnapshot:
    def test_defaults(self) -> None:
        sid = BackupId(value="snap-1")
        snap = BackupSnapshot(snapshot_id=sid)
        assert snap.snapshot_id.value == "snap-1"
        assert snap.backup_ids == ()

    def test_with_backups(self) -> None:
        sid = BackupId(value="snap-2")
        snap = BackupSnapshot(snapshot_id=sid, backup_ids=("bkp-1", "bkp-2"), label="weekly")
        assert snap.label == "weekly"
        assert snap.backup_ids == ("bkp-1", "bkp-2")


class TestRestoreOperation:
    def test_defaults(self) -> None:
        rid = BackupId(value="rest-1")
        op = RestoreOperation(restore_id=rid, backup_id="bkp-1", status=BackupStatus.PENDING)
        assert op.restore_id.value == "rest-1"
        assert op.verified is False

    def test_with_scope(self) -> None:
        rid = BackupId(value="rest-2")
        op = RestoreOperation(restore_id=rid, backup_id="bkp-1", status=BackupStatus.COMPLETED, scope="database", dry_run=True)
        assert op.scope == "database"
        assert op.dry_run is True


class TestRetentionPolicy:
    def test_defaults(self) -> None:
        rp = RetentionPolicy()
        assert rp.max_full_backups == 7
        assert rp.retention_days == 90
        assert rp.retention_by_count is True
        assert rp.retention_by_age is True

    def test_custom(self) -> None:
        rp = RetentionPolicy(max_full_backups=3, retention_days=30)
        assert rp.max_full_backups == 3
        assert rp.retention_days == 30


class TestBackupSchedule:
    def test_construction(self) -> None:
        sid = BackupId(value="sched-1")
        sched = BackupSchedule(
            schedule_id=sid,
            name="Daily Backup",
            frequency=ScheduleFrequency.DAILY,
            backup_type="full",
        )
        assert sched.name == "Daily Backup"
        assert sched.frequency == ScheduleFrequency.DAILY
        assert sched.enabled is True

    def test_cron(self) -> None:
        sid = BackupId(value="sched-2")
        sched = BackupSchedule(
            schedule_id=sid,
            name="Custom Cron",
            frequency=ScheduleFrequency.CRON,
            cron_expression="0 2 * * *",
        )
        assert sched.cron_expression == "0 2 * * *"


class TestScheduleFrequency:
    def test_values(self) -> None:
        assert ScheduleFrequency.MANUAL.value == "manual"
        assert ScheduleFrequency.DAILY.value == "daily"
        assert ScheduleFrequency.WEEKLY.value == "weekly"
        assert ScheduleFrequency.MONTHLY.value == "monthly"
        assert ScheduleFrequency.CRON.value == "cron"


class TestBackupVerification:
    def test_construction(self) -> None:
        vid = BackupId(value="ver-1")
        v = BackupVerification(
            verification_id=vid,
            backup_id="bkp-1",
            checksum_valid=True,
            archive_integrity=True,
            restore_simulation=True,
        )
        assert v.checksum_valid is True
        assert v.duration_ms == 0


class TestDisasterRecoveryPlan:
    def test_construction(self) -> None:
        pid = BackupId(value="dr-1")
        items = (
            RecoveryChecklistItem(item_id="c1", description="Stop services"),
            RecoveryChecklistItem(item_id="c2", description="Restore database"),
        )
        plan = DisasterRecoveryPlan(
            plan_id=pid,
            name="Main DR Plan",
            description="Production recovery",
            estimated_downtime_minutes=120,
            checklist=items,
        )
        assert plan.name == "Main DR Plan"
        assert len(plan.checklist) == 2
        assert plan.checklist[0].description == "Stop services"


class TestRecoveryChecklistItem:
    def test_construction(self) -> None:
        item = RecoveryChecklistItem(item_id="c1", description="Verify backups")
        assert item.completed is False
        assert item.completed_at == ""


class TestRecoveryTest:
    def test_construction(self) -> None:
        tid = BackupId(value="rt-1")
        test = RecoveryTest(
            test_id=tid,
            plan_id="dr-1",
            status=RecoveryStatus.COMPLETED,
            executed_by="admin",
        )
        assert test.status == RecoveryStatus.COMPLETED
        assert test.executed_by == "admin"


class TestRecoveryStatus:
    def test_values(self) -> None:
        assert RecoveryStatus.NOT_STARTED.value == "not_started"
        assert RecoveryStatus.IN_PROGRESS.value == "in_progress"
        assert RecoveryStatus.COMPLETED.value == "completed"
        assert RecoveryStatus.FAILED.value == "failed"
        assert RecoveryStatus.TESTING.value == "testing"


class TestComponentHealth:
    def test_values(self) -> None:
        assert ComponentHealth.HEALTHY.value == "healthy"
        assert ComponentHealth.DEGRADED.value == "degraded"
        assert ComponentHealth.UNHEALTHY.value == "unhealthy"
        assert ComponentHealth.UNKNOWN.value == "unknown"


class TestComponentHealthStatus:
    def test_construction(self) -> None:
        status = ComponentHealthStatus(
            component="database",
            health=ComponentHealth.HEALTHY,
            message="All good",
        )
        assert status.component == "database"
        assert status.health == ComponentHealth.HEALTHY


class TestHealthReport:
    def test_construction(self) -> None:
        rid = BackupId(value="hr-1")
        report = HealthReport(
            report_id=rid,
            overall=ComponentHealth.HEALTHY,
            database_healthy=True,
            storage_healthy=True,
            workers_healthy=True,
            backup_service_healthy=True,
        )
        assert report.overall == ComponentHealth.HEALTHY
        assert report.database_healthy is True


class TestRestoreScope:
    def test_values(self) -> None:
        assert RestoreScope.DATABASE.value == "database"
        assert RestoreScope.CONFIGURATION.value == "configuration"
        assert RestoreScope.REPORTS.value == "reports"
        assert RestoreScope.COMPLETE.value == "complete"
        assert RestoreScope.AUDIT_LOGS.value == "audit_logs"


class TestCompressionFormat:
    def test_values(self) -> None:
        assert CompressionFormat.ZIP.value == "zip"
        assert CompressionFormat.TAR_GZ.value == "tar_gz"
