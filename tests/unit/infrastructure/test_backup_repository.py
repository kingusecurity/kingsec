from __future__ import annotations

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
    RecoveryTest,
    RestoreOperation,
    ScheduleFrequency,
)
from kingsec.infrastructure.backup.repository import InMemoryBackupRepository


class TestInMemoryBackupRepository:
    def test_save_and_find_backup(self) -> None:
        repo = InMemoryBackupRepository()
        bid = BackupId(value="bkp-1")
        bm = BackupMetadata(backup_id=bid, backup_type=BackupType.FULL, status=BackupStatus.COMPLETED)
        repo.save_backup(bm)
        found = repo.find_backup_by_id("bkp-1")
        assert found is not None
        assert found.backup_id.value == "bkp-1"

    def test_find_all_backups(self) -> None:
        repo = InMemoryBackupRepository()
        repo.save_backup(
            BackupMetadata(
                backup_id=BackupId(value="bkp-1"),
                backup_type=BackupType.FULL,
                status=BackupStatus.COMPLETED,
            )
        )
        repo.save_backup(
            BackupMetadata(
                backup_id=BackupId(value="bkp-2"),
                backup_type=BackupType.INCREMENTAL,
                status=BackupStatus.PENDING,
            )
        )
        assert len(repo.find_all_backups()) == 2

    def test_delete_backup(self) -> None:
        repo = InMemoryBackupRepository()
        bid = BackupId(value="bkp-1")
        repo.save_backup(BackupMetadata(backup_id=bid, backup_type=BackupType.FULL, status=BackupStatus.PENDING))
        repo.delete_backup("bkp-1")
        assert repo.find_backup_by_id("bkp-1") is None

    def test_delete_backup_nonexistent(self) -> None:
        repo = InMemoryBackupRepository()
        repo.delete_backup("missing")  # no-op

    def test_save_and_find_snapshot(self) -> None:
        repo = InMemoryBackupRepository()
        sid = BackupId(value="snap-1")
        snap = BackupSnapshot(snapshot_id=sid, label="weekly")
        repo.save_snapshot(snap)
        found = repo.find_snapshot_by_id("snap-1")
        assert found is not None
        assert found.label == "weekly"

    def test_find_all_snapshots(self) -> None:
        repo = InMemoryBackupRepository()
        repo.save_snapshot(BackupSnapshot(snapshot_id=BackupId(value="snap-1")))
        repo.save_snapshot(BackupSnapshot(snapshot_id=BackupId(value="snap-2")))
        assert len(repo.find_all_snapshots()) == 2

    def test_delete_snapshot(self) -> None:
        repo = InMemoryBackupRepository()
        repo.save_snapshot(BackupSnapshot(snapshot_id=BackupId(value="snap-1")))
        repo.delete_snapshot("snap-1")
        assert repo.find_snapshot_by_id("snap-1") is None

    def test_save_and_find_restore(self) -> None:
        repo = InMemoryBackupRepository()
        rid = BackupId(value="rest-1")
        op = RestoreOperation(restore_id=rid, backup_id="bkp-1", status=BackupStatus.COMPLETED.value)
        repo.save_restore(op)
        found = repo.find_restore_by_id("rest-1")
        assert found is not None
        assert found.backup_id == "bkp-1"

    def test_save_and_find_schedule(self) -> None:
        repo = InMemoryBackupRepository()
        sched = BackupSchedule(schedule_id=BackupId(value="s-1"), name="Daily", frequency=ScheduleFrequency.DAILY)
        repo.save_schedule(sched)
        found = repo.find_schedule_by_id("s-1")
        assert found is not None
        assert found.name == "Daily"

    def test_find_all_schedules(self) -> None:
        repo = InMemoryBackupRepository()
        repo.save_schedule(BackupSchedule(schedule_id=BackupId(value="s-1"), name="A", frequency=ScheduleFrequency.DAILY))
        repo.save_schedule(BackupSchedule(schedule_id=BackupId(value="s-2"), name="B", frequency=ScheduleFrequency.WEEKLY))
        assert len(repo.find_all_schedules()) == 2

    def test_delete_schedule(self) -> None:
        repo = InMemoryBackupRepository()
        repo.save_schedule(BackupSchedule(schedule_id=BackupId(value="s-1"), name="A", frequency=ScheduleFrequency.DAILY))
        repo.delete_schedule("s-1")
        assert repo.find_schedule_by_id("s-1") is None

    def test_delete_schedule_nonexistent(self) -> None:
        repo = InMemoryBackupRepository()
        repo.delete_schedule("missing")

    def test_save_and_find_verification(self) -> None:
        repo = InMemoryBackupRepository()
        v = BackupVerification(verification_id=BackupId(value="v-1"), backup_id="bkp-1", checksum_valid=True)
        repo.save_verification(v)
        found = repo.find_verification_by_id("v-1")
        assert found is not None
        assert found.checksum_valid is True

    def test_find_all_verifications(self) -> None:
        repo = InMemoryBackupRepository()
        repo.save_verification(BackupVerification(verification_id=BackupId(value="v-1"), backup_id="bkp-1"))
        repo.save_verification(BackupVerification(verification_id=BackupId(value="v-2"), backup_id="bkp-2"))
        assert len(repo.find_all_verifications()) == 2

    def test_find_verifications_by_backup(self) -> None:
        repo = InMemoryBackupRepository()
        repo.save_verification(BackupVerification(verification_id=BackupId(value="v-1"), backup_id="bkp-1"))
        repo.save_verification(BackupVerification(verification_id=BackupId(value="v-2"), backup_id="bkp-2"))
        repo.save_verification(BackupVerification(verification_id=BackupId(value="v-3"), backup_id="bkp-1"))
        results = repo.find_verifications_by_backup("bkp-1")
        assert len(results) == 2

    def test_save_and_find_recovery_plan(self) -> None:
        repo = InMemoryBackupRepository()
        items = (RecoveryChecklistItem(item_id="c1", description="Step 1"),)
        plan = DisasterRecoveryPlan(plan_id=BackupId(value="dr-1"), name="DR", checklist=items)
        repo.save_recovery_plan(plan)
        found = repo.find_recovery_plan_by_id("dr-1")
        assert found is not None
        assert found.name == "DR"

    def test_find_all_recovery_plans(self) -> None:
        repo = InMemoryBackupRepository()
        repo.save_recovery_plan(DisasterRecoveryPlan(plan_id=BackupId(value="dr-1"), name="DR1"))
        repo.save_recovery_plan(DisasterRecoveryPlan(plan_id=BackupId(value="dr-2"), name="DR2"))
        assert len(repo.find_all_recovery_plans()) == 2

    def test_delete_recovery_plan(self) -> None:
        repo = InMemoryBackupRepository()
        repo.save_recovery_plan(DisasterRecoveryPlan(plan_id=BackupId(value="dr-1"), name="DR"))
        repo.delete_recovery_plan("dr-1")
        assert repo.find_recovery_plan_by_id("dr-1") is None

    def test_delete_recovery_plan_nonexistent(self) -> None:
        repo = InMemoryBackupRepository()
        repo.delete_recovery_plan("missing")

    def test_save_and_find_recovery_test(self) -> None:
        repo = InMemoryBackupRepository()
        rt = RecoveryTest(test_id=BackupId(value="rt-1"), plan_id="dr-1", status=RecoveryStatus.COMPLETED)
        repo.save_recovery_test(rt)
        found = repo.find_recovery_test_by_id("rt-1")
        assert found is not None
        assert found.plan_id == "dr-1"

    def test_find_all_recovery_tests(self) -> None:
        repo = InMemoryBackupRepository()
        repo.save_recovery_test(RecoveryTest(test_id=BackupId(value="rt-1"), plan_id="dr-1", status=RecoveryStatus.COMPLETED))
        repo.save_recovery_test(RecoveryTest(test_id=BackupId(value="rt-2"), plan_id="dr-1", status=RecoveryStatus.COMPLETED))
        assert len(repo.find_all_recovery_tests()) == 2

    def test_find_recovery_tests_by_plan(self) -> None:
        repo = InMemoryBackupRepository()
        repo.save_recovery_test(RecoveryTest(test_id=BackupId(value="rt-1"), plan_id="dr-1", status=RecoveryStatus.COMPLETED))
        repo.save_recovery_test(RecoveryTest(test_id=BackupId(value="rt-2"), plan_id="dr-2", status=RecoveryStatus.COMPLETED))
        results = repo.find_recovery_tests_by_plan("dr-1")
        assert len(results) == 1
        assert results[0].plan_id == "dr-1"
