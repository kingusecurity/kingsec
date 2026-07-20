from __future__ import annotations

from kingsec.domain.backup import (
    BackupId,
    BackupMetadata,
    BackupSnapshot,
    BackupStatus,
    BackupType,
    RestoreOperation,
    RetentionPolicy,
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
        assert BackupType.SNAPSHOT.value == "snapshot"


class TestBackupStatus:
    def test_values(self) -> None:
        assert BackupStatus.PENDING.value == "pending"
        assert BackupStatus.RUNNING.value == "running"
        assert BackupStatus.COMPLETED.value == "completed"
        assert BackupStatus.FAILED.value == "failed"
        assert BackupStatus.RESTORING.value == "restoring"


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


class TestRetentionPolicy:
    def test_defaults(self) -> None:
        rp = RetentionPolicy()
        assert rp.max_full_backups == 7
        assert rp.retention_days == 90

    def test_custom(self) -> None:
        rp = RetentionPolicy(max_full_backups=3, retention_days=30)
        assert rp.max_full_backups == 3
        assert rp.retention_days == 30
