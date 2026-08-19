from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from kingsec.application.errors import BackupNotFoundError
from kingsec.application.ports.outbound import (
    BackupCompressionPort,
    BackupEncryptionPort,
    BackupRepositoryPort,
    BackupStoragePort,
)
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.use_cases.backup import (
    CleanupExpiredBackups,
    CreateBackup,
    CreateRecoveryPlan,
    CreateSchedule,
    CreateSnapshot,
    DeleteBackup,
    DeleteRecoveryPlan,
    DeleteSchedule,
    GetHealthReport,
    GetRecoveryPlan,
    GetSchedule,
    ListBackups,
    ListRecoveryPlans,
    ListRecoveryTests,
    ListSchedules,
    ListVerifications,
    RestoreBackup,
    RestoreSnapshot,
    RestoreWithScope,
    RunRecoveryTest,
    UpdateRecoveryPlan,
    UpdateSchedule,
    ValidateBackup,
    VerifyBackup,
    VerifyRestore,
)
from kingsec.domain.backup import (
    BackupId,
    BackupMetadata,
    BackupSchedule,
    BackupSnapshot,
    BackupStatus,
    BackupType,
    BackupVerification,
    DisasterRecoveryPlan,
    RecoveryChecklistItem,
    RecoveryStatus,
    RetentionPolicy,
    ScheduleFrequency,
)


@pytest.fixture
def repo() -> MagicMock:
    return MagicMock(spec=BackupRepositoryPort)


@pytest.fixture
def storage() -> MagicMock:
    s = MagicMock(spec=BackupStoragePort)
    s.write.return_value = "/path/to/backup.bkp"
    s.read.return_value = b"encrypted-compressed-data"
    s.exists.return_value = True
    return s


@pytest.fixture
def encryption() -> MagicMock:
    e = MagicMock(spec=BackupEncryptionPort)
    e.encrypt.side_effect = lambda x: b"enc-" + x
    e.decrypt.side_effect = lambda x: x[4:] if x.startswith(b"enc-") else x
    return e


@pytest.fixture
def compression() -> MagicMock:
    c = MagicMock(spec=BackupCompressionPort)
    c.compress.side_effect = lambda x: b"cmp-" + x
    c.decompress.side_effect = lambda x: x[4:] if x.startswith(b"cmp-") else x
    return c


@pytest.fixture
def audit() -> MagicMock:
    return MagicMock(spec=AuditPublisher)


class TestCreateBackup:
    def test_create_full_backup(self, repo, storage, encryption, compression, audit) -> None:
        uc = CreateBackup(repo, storage, encryption, compression, audit)
        result = uc.execute(backup_type="full", owner_user_id="u1")
        assert result.status == BackupStatus.COMPLETED
        assert result.backup_type == BackupType.FULL
        assert result.encrypted is True
        assert result.compressed is True
        assert result.owner_user_id == "u1"
        repo.save_backup.assert_called()
        storage.write.assert_called_once()
        audit.record.assert_called()

    def test_create_incremental_backup(self, repo, storage, encryption, compression, audit) -> None:
        uc = CreateBackup(repo, storage, encryption, compression, audit)
        result = uc.execute(backup_type="incremental")
        assert result.backup_type == BackupType.INCREMENTAL

    def test_backup_failure_sets_failed_status(self, repo, storage, encryption, compression, audit) -> None:
        storage.write.side_effect = Exception("Disk full")
        uc = CreateBackup(repo, storage, encryption, compression, audit)
        result = uc.execute(backup_type="full")
        assert result.status == BackupStatus.FAILED
        assert "Disk full" in result.error_message

    def test_unencrypted_backup(self, repo, storage, encryption, compression, audit) -> None:
        uc = CreateBackup(repo, storage, encryption, compression, audit)
        result = uc.execute(backup_type="full", encrypt=False)
        assert result.encrypted is False


class TestRestoreBackup:
    def test_restore_success(self, repo, storage, encryption, compression, audit) -> None:
        bid = BackupId(value="bkp-1")
        backup = BackupMetadata(
            backup_id=bid,
            backup_type=BackupType.FULL,
            status=BackupStatus.COMPLETED,
            encrypted=True,
            compressed=True,
            checksum="",
        )
        repo.find_backup_by_id.return_value = backup
        uc = RestoreBackup(repo, storage, encryption, compression, audit)
        result = uc.execute("bkp-1")
        assert result.status == BackupStatus.COMPLETED

    def test_restore_not_found(self, repo, storage, encryption, compression, audit) -> None:
        repo.find_backup_by_id.return_value = None
        uc = RestoreBackup(repo, storage, encryption, compression, audit)
        with pytest.raises(BackupNotFoundError):
            uc.execute("bkp-missing")

    def test_restore_failure(self, repo, storage, encryption, compression, audit) -> None:
        bid = BackupId(value="bkp-1")
        backup = BackupMetadata(
            backup_id=bid,
            backup_type=BackupType.FULL,
            status=BackupStatus.COMPLETED,
            encrypted=True,
            compressed=True,
            checksum="",
        )
        repo.find_backup_by_id.return_value = backup
        storage.read.return_value = None
        uc = RestoreBackup(repo, storage, encryption, compression, audit)
        result = uc.execute("bkp-1")
        assert result.status == BackupStatus.FAILED


class TestListBackups:
    def test_list(self, repo) -> None:
        repo.find_all_backups.return_value = [
            BackupMetadata(
                backup_id=BackupId(value="bkp-1"), backup_type=BackupType.FULL, status=BackupStatus.COMPLETED
            ),
        ]
        uc = ListBackups(repo)
        result = uc.execute()
        assert len(result) == 1

    def test_list_empty(self, repo) -> None:
        repo.find_all_backups.return_value = []
        uc = ListBackups(repo)
        assert uc.execute() == []


class TestDeleteBackup:
    def test_delete(self, repo, storage, audit) -> None:
        repo.find_backup_by_id.return_value = BackupMetadata(
            backup_id=BackupId(value="bkp-1"),
            backup_type=BackupType.FULL,
            status=BackupStatus.COMPLETED,
        )
        uc = DeleteBackup(repo, storage, audit)
        uc.execute("bkp-1")
        repo.delete_backup.assert_called_with("bkp-1")
        storage.delete.assert_called_with("bkp-1")
        audit.record.assert_called_once()

    def test_delete_not_found(self, repo, storage, audit) -> None:
        repo.find_backup_by_id.return_value = None
        uc = DeleteBackup(repo, storage, audit)
        with pytest.raises(BackupNotFoundError):
            uc.execute("bkp-missing")


class TestValidateBackup:
    def test_valid(self, repo, storage, encryption, compression) -> None:
        repo.find_backup_by_id.return_value = BackupMetadata(
            backup_id=BackupId(value="bkp-1"),
            backup_type=BackupType.FULL,
            status=BackupStatus.COMPLETED,
            encrypted=True,
            compressed=True,
        )
        uc = ValidateBackup(repo, storage, encryption, compression)
        assert uc.execute("bkp-1") is True

    def test_invalid_not_found(self, repo, storage, encryption, compression) -> None:
        repo.find_backup_by_id.return_value = None
        uc = ValidateBackup(repo, storage, encryption, compression)
        with pytest.raises(BackupNotFoundError):
            uc.execute("bkp-missing")

    def test_invalid_data(self, repo, storage, encryption, compression) -> None:
        repo.find_backup_by_id.return_value = BackupMetadata(
            backup_id=BackupId(value="bkp-1"),
            backup_type=BackupType.FULL,
            status=BackupStatus.COMPLETED,
            encrypted=True,
            compressed=True,
        )
        storage.read.return_value = None
        uc = ValidateBackup(repo, storage, encryption, compression)
        assert uc.execute("bkp-1") is False


class TestCreateSnapshot:
    def test_create(self, repo, audit) -> None:
        uc = CreateSnapshot(repo, audit)
        result = uc.execute(label="weekly", backup_ids=["bkp-1", "bkp-2"])
        assert result.label == "weekly"
        assert result.backup_ids == ("bkp-1", "bkp-2")
        repo.save_snapshot.assert_called_once()
        audit.record.assert_called_once()


class TestRestoreSnapshot:
    def test_restore(self, repo, audit) -> None:
        snap = BackupSnapshot(
            snapshot_id=BackupId(value="snap-1"),
            backup_ids=("bkp-1",),
        )
        repo.find_snapshot_by_id.return_value = snap
        restore_uc = MagicMock()
        restore_uc.execute.return_value = MagicMock(status=BackupStatus.COMPLETED)
        uc = RestoreSnapshot(repo, restore_uc, audit)
        results = uc.execute("snap-1")
        assert len(results) == 1

    def test_restore_not_found(self, repo, audit) -> None:
        repo.find_snapshot_by_id.return_value = None
        restore_uc = MagicMock()
        uc = RestoreSnapshot(repo, restore_uc, audit)
        from kingsec.application.errors import SnapshotNotFoundError

        with pytest.raises(SnapshotNotFoundError):
            uc.execute("snap-missing")


class TestVerifyRestore:
    def test_verified(self, repo) -> None:
        op = MagicMock(status=BackupStatus.COMPLETED, error_message="")
        repo.find_restore_by_id.return_value = op
        uc = VerifyRestore(repo)
        assert uc.execute("rest-1") is True

    def test_not_verified(self, repo) -> None:
        op = MagicMock(status=BackupStatus.FAILED, error_message="error")
        repo.find_restore_by_id.return_value = op
        uc = VerifyRestore(repo)
        assert uc.execute("rest-1") is False

    def test_not_found(self, repo) -> None:
        repo.find_restore_by_id.return_value = None
        uc = VerifyRestore(repo)
        from kingsec.application.errors import RestoreNotFoundError

        with pytest.raises(RestoreNotFoundError):
            uc.execute("rest-missing")


class TestCleanupExpiredBackups:
    def test_cleanup_removes_excess_full(self, repo, storage, audit) -> None:
        # find_all_backups() returns newest-first in production (ORDER BY
        # created_at DESC), so bkp-0 is the newest and bkp-4 is the oldest.
        backups = [
            BackupMetadata(
                backup_id=BackupId(value=f"bkp-{i}"), backup_type=BackupType.FULL, status=BackupStatus.COMPLETED
            )
            for i in range(5)
        ]
        repo.find_all_backups.return_value = backups
        policy = RetentionPolicy(max_full_backups=2, max_incremental_backups=10)
        uc = CleanupExpiredBackups(repo, storage, audit, policy)
        deleted = uc.execute()
        assert deleted == 3
        # The two newest backups (bkp-0, bkp-1) must survive; only the
        # three oldest (bkp-2, bkp-3, bkp-4) may be deleted.
        deleted_ids = {call.args[0] for call in repo.delete_backup.call_args_list}
        assert deleted_ids == {"bkp-2", "bkp-3", "bkp-4"}

    def test_cleanup_removes_excess_incremental(self, repo, storage, audit) -> None:
        backups = [
            BackupMetadata(
                backup_id=BackupId(value=f"bkp-{i}"), backup_type=BackupType.INCREMENTAL, status=BackupStatus.COMPLETED
            )
            for i in range(5)
        ]
        repo.find_all_backups.return_value = backups
        policy = RetentionPolicy(max_full_backups=10, max_incremental_backups=2)
        uc = CleanupExpiredBackups(repo, storage, audit, policy)
        deleted = uc.execute()
        assert deleted == 3
        deleted_ids = {call.args[0] for call in repo.delete_backup.call_args_list}
        assert deleted_ids == {"bkp-2", "bkp-3", "bkp-4"}

    def test_cleanup_no_excess(self, repo, storage, audit) -> None:
        backups = [
            BackupMetadata(
                backup_id=BackupId(value="bkp-1"), backup_type=BackupType.FULL, status=BackupStatus.COMPLETED
            ),
        ]
        repo.find_all_backups.return_value = backups
        uc = CleanupExpiredBackups(repo, storage, audit)
        deleted = uc.execute()
        assert deleted == 0


class TestRestoreWithScope:
    def test_restore_complete(self, repo, storage, encryption, compression, audit) -> None:
        bid = BackupId(value="bkp-1")
        backup = BackupMetadata(
            backup_id=bid, backup_type=BackupType.FULL, status=BackupStatus.COMPLETED,
            encrypted=True, compressed=True, checksum="",
        )
        repo.find_backup_by_id.return_value = backup
        uc = RestoreWithScope(repo, storage, encryption, compression, audit)
        result = uc.execute("bkp-1", scope="complete", dry_run=False)
        assert result.status == BackupStatus.COMPLETED
        assert result.scope == "complete"
        assert result.dry_run is False

    def test_restore_dry_run(self, repo, storage, encryption, compression, audit) -> None:
        bid = BackupId(value="bkp-1")
        backup = BackupMetadata(
            backup_id=bid, backup_type=BackupType.FULL, status=BackupStatus.COMPLETED,
            encrypted=True, compressed=True, checksum="",
        )
        repo.find_backup_by_id.return_value = backup
        uc = RestoreWithScope(repo, storage, encryption, compression, audit)
        result = uc.execute("bkp-1", scope="database", dry_run=True)
        assert result.dry_run is True
        assert result.scope == "database"

    def test_restore_not_found(self, repo, storage, encryption, compression, audit) -> None:
        repo.find_backup_by_id.return_value = None
        uc = RestoreWithScope(repo, storage, encryption, compression, audit)
        with pytest.raises(BackupNotFoundError):
            uc.execute("bkp-missing")


class TestVerifyBackup:
    def test_verify_success(self, repo, storage, encryption, compression, audit) -> None:
        bid = BackupId(value="bkp-1")
        backup = BackupMetadata(
            backup_id=bid, backup_type=BackupType.FULL, status=BackupStatus.COMPLETED,
            encrypted=True, compressed=True,
        )
        repo.find_backup_by_id.return_value = backup
        uc = VerifyBackup(repo, storage, encryption, compression, audit)
        result = uc.execute("bkp-1", verified_by="admin")
        assert result.checksum_valid is True
        assert result.archive_integrity is True
        assert result.restore_simulation is True
        repo.save_verification.assert_called_once()

    def test_verify_not_found(self, repo, storage, encryption, compression, audit) -> None:
        repo.find_backup_by_id.return_value = None
        uc = VerifyBackup(repo, storage, encryption, compression, audit)
        with pytest.raises(BackupNotFoundError):
            uc.execute("bkp-missing")


class TestListVerifications:
    def test_list_all(self, repo) -> None:
        repo.find_all_verifications.return_value = [
            BackupVerification(verification_id=BackupId(value="v1"), backup_id="bkp-1", checksum_valid=True),
        ]
        uc = ListVerifications(repo)
        result = uc.execute()
        assert len(result) == 1

    def test_list_by_backup(self, repo) -> None:
        repo.find_verifications_by_backup.return_value = [
            BackupVerification(verification_id=BackupId(value="v1"), backup_id="bkp-1", checksum_valid=True),
        ]
        uc = ListVerifications(repo)
        result = uc.execute(backup_id="bkp-1")
        assert len(result) == 1


class TestCreateSchedule:
    def test_create(self, repo, audit) -> None:
        sched = BackupSchedule(
            schedule_id=BackupId(value="sched-new"),
            name="Daily",
            frequency=ScheduleFrequency.DAILY,
        )
        uc = CreateSchedule(repo, audit)
        result = uc.execute(sched)
        assert result.name == "Daily"
        repo.save_schedule.assert_called_once()
        audit.record.assert_called_once()


class TestUpdateSchedule:
    def test_update(self, repo, audit) -> None:
        existing = BackupSchedule(
            schedule_id=BackupId(value="sched-1"),
            name="Old Name",
            frequency=ScheduleFrequency.DAILY,
        )
        repo.find_schedule_by_id.return_value = existing
        uc = UpdateSchedule(repo, audit)
        result = uc.execute("sched-1", name="New Name")
        assert result.name == "New Name"

    def test_update_not_found(self, repo, audit) -> None:
        repo.find_schedule_by_id.return_value = None
        uc = UpdateSchedule(repo, audit)
        from kingsec.application.errors import ScheduleNotFoundError
        with pytest.raises(ScheduleNotFoundError):
            uc.execute("sched-missing")


class TestDeleteSchedule:
    def test_delete(self, repo, audit) -> None:
        existing = BackupSchedule(
            schedule_id=BackupId(value="sched-1"), name="Daily", frequency=ScheduleFrequency.DAILY,
        )
        repo.find_schedule_by_id.return_value = existing
        uc = DeleteSchedule(repo, audit)
        uc.execute("sched-1")
        repo.delete_schedule.assert_called_with("sched-1")

    def test_delete_not_found(self, repo, audit) -> None:
        repo.find_schedule_by_id.return_value = None
        uc = DeleteSchedule(repo, audit)
        from kingsec.application.errors import ScheduleNotFoundError
        with pytest.raises(ScheduleNotFoundError):
            uc.execute("sched-missing")


class TestListSchedules:
    def test_list(self, repo) -> None:
        repo.find_all_schedules.return_value = [
            BackupSchedule(schedule_id=BackupId(value="s1"), name="D", frequency=ScheduleFrequency.DAILY),
        ]
        uc = ListSchedules(repo)
        assert len(uc.execute()) == 1


class TestGetSchedule:
    def test_get(self, repo) -> None:
        sched = BackupSchedule(schedule_id=BackupId(value="s1"), name="D", frequency=ScheduleFrequency.DAILY)
        repo.find_schedule_by_id.return_value = sched
        uc = GetSchedule(repo)
        assert uc.execute("s1").name == "D"

    def test_get_not_found(self, repo) -> None:
        repo.find_schedule_by_id.return_value = None
        uc = GetSchedule(repo)
        from kingsec.application.errors import ScheduleNotFoundError
        with pytest.raises(ScheduleNotFoundError):
            uc.execute("s-missing")


class TestCreateRecoveryPlan:
    def test_create(self, repo, audit) -> None:
        items = (RecoveryChecklistItem(item_id="c1", description="Step 1"),)
        plan = DisasterRecoveryPlan(
            plan_id=BackupId(value="dr-new"), name="DR Plan", checklist=items,
        )
        uc = CreateRecoveryPlan(repo, audit)
        result = uc.execute(plan)
        assert result.name == "DR Plan"
        repo.save_recovery_plan.assert_called_once()


class TestUpdateRecoveryPlan:
    def test_update(self, repo, audit) -> None:
        existing = DisasterRecoveryPlan(
            plan_id=BackupId(value="dr-1"), name="Old Plan",
        )
        repo.find_recovery_plan_by_id.return_value = existing
        uc = UpdateRecoveryPlan(repo, audit)
        result = uc.execute("dr-1", name="New Plan")
        assert result.name == "New Plan"

    def test_update_downtime_from_string(self, repo, audit) -> None:
        """Phase 12 mypy fix: estimated_downtime_minutes=int(kwargs.get(...))
        used to have a mismatched type: ignore comment that suppressed the
        wrong error code, leaving int() called on a plain `object`-typed
        value with no real narrowing. A caller-supplied string (the
        realistic shape for a form-submitted value) must still coerce."""
        existing = DisasterRecoveryPlan(plan_id=BackupId(value="dr-1"), name="Plan", estimated_downtime_minutes=10)
        repo.find_recovery_plan_by_id.return_value = existing
        uc = UpdateRecoveryPlan(repo, audit)
        result = uc.execute("dr-1", estimated_downtime_minutes="45")
        assert result.estimated_downtime_minutes == 45

    def test_update_downtime_unparseable_falls_back_to_existing(self, repo, audit) -> None:
        """A value that isn't str/int/float (e.g. a nested dict from a
        malformed request) must not crash the use case - falls back to the
        existing value rather than raising, matching this codebase's
        fail-safe-not-fail-closed convention for non-security-relevant
        input coercion."""
        existing = DisasterRecoveryPlan(plan_id=BackupId(value="dr-1"), name="Plan", estimated_downtime_minutes=10)
        repo.find_recovery_plan_by_id.return_value = existing
        uc = UpdateRecoveryPlan(repo, audit)
        result = uc.execute("dr-1", estimated_downtime_minutes={"bad": "shape"})
        assert result.estimated_downtime_minutes == 10

    def test_update_not_found(self, repo, audit) -> None:
        repo.find_recovery_plan_by_id.return_value = None
        uc = UpdateRecoveryPlan(repo, audit)
        from kingsec.application.errors import RecoveryPlanNotFoundError
        with pytest.raises(RecoveryPlanNotFoundError):
            uc.execute("dr-missing")


class TestDeleteRecoveryPlan:
    def test_delete(self, repo, audit) -> None:
        existing = DisasterRecoveryPlan(plan_id=BackupId(value="dr-1"), name="DR")
        repo.find_recovery_plan_by_id.return_value = existing
        uc = DeleteRecoveryPlan(repo, audit)
        uc.execute("dr-1")
        repo.delete_recovery_plan.assert_called_with("dr-1")

    def test_delete_not_found(self, repo, audit) -> None:
        repo.find_recovery_plan_by_id.return_value = None
        uc = DeleteRecoveryPlan(repo, audit)
        from kingsec.application.errors import RecoveryPlanNotFoundError
        with pytest.raises(RecoveryPlanNotFoundError):
            uc.execute("dr-missing")


class TestListRecoveryPlans:
    def test_list(self, repo) -> None:
        repo.find_all_recovery_plans.return_value = [
            DisasterRecoveryPlan(plan_id=BackupId(value="dr-1"), name="DR"),
        ]
        uc = ListRecoveryPlans(repo)
        assert len(uc.execute()) == 1


class TestGetRecoveryPlan:
    def test_get(self, repo) -> None:
        plan = DisasterRecoveryPlan(plan_id=BackupId(value="dr-1"), name="DR")
        repo.find_recovery_plan_by_id.return_value = plan
        uc = GetRecoveryPlan(repo)
        assert uc.execute("dr-1").name == "DR"

    def test_get_not_found(self, repo) -> None:
        repo.find_recovery_plan_by_id.return_value = None
        uc = GetRecoveryPlan(repo)
        from kingsec.application.errors import RecoveryPlanNotFoundError
        with pytest.raises(RecoveryPlanNotFoundError):
            uc.execute("dr-missing")


class RecoveryTestUseCaseTests:
    def test_test_recovery(self, repo, audit) -> None:
        items = (RecoveryChecklistItem(item_id="c1", description="Step 1"),)
        plan = DisasterRecoveryPlan(plan_id=BackupId(value="dr-1"), name="DR", checklist=items)
        repo.find_recovery_plan_by_id.return_value = plan
        uc = RunRecoveryTest(repo, audit)
        result = uc.execute("dr-1", executed_by="admin")
        assert result.status == RecoveryStatus.COMPLETED
        assert result.executed_by == "admin"
        repo.save_recovery_test.assert_called_once()

    def test_test_not_found(self, repo, audit) -> None:
        repo.find_recovery_plan_by_id.return_value = None
        uc = RunRecoveryTest(repo, audit)
        from kingsec.application.errors import RecoveryPlanNotFoundError
        with pytest.raises(RecoveryPlanNotFoundError):
            uc.execute("dr-missing")


class TestListRecoveryTests:
    def test_list_all(self, repo) -> None:
        repo.find_all_recovery_tests.return_value = []
        uc = ListRecoveryTests(repo)
        assert uc.execute() == []

    def test_list_by_plan(self, repo) -> None:
        repo.find_recovery_tests_by_plan.return_value = []
        uc = ListRecoveryTests(repo)
        assert uc.execute(plan_id="dr-1") == []


class TestGetHealthReport:
    def test_report_healthy(self, repo) -> None:
        repo.find_all_backups.return_value = [
            BackupMetadata(backup_id=BackupId(value="bkp-1"), backup_type=BackupType.FULL, status=BackupStatus.COMPLETED),
        ]
        uc = GetHealthReport(repo)
        report = uc.execute()
        assert report.database_healthy is True
        assert report.storage_healthy is True

    def test_report_no_backups(self, repo) -> None:
        repo.find_all_backups.return_value = []
        uc = GetHealthReport(repo)
        report = uc.execute()
        assert report.overall.value == "healthy"
