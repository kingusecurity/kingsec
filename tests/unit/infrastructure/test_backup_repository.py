from __future__ import annotations

from kingsec.domain.backup import (
    BackupId,
    BackupMetadata,
    BackupSnapshot,
    BackupStatus,
    BackupType,
    RestoreOperation,
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
