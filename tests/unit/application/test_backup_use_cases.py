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
    CreateSnapshot,
    DeleteBackup,
    ListBackups,
    RestoreBackup,
    RestoreSnapshot,
    ValidateBackup,
    VerifyRestore,
)
from kingsec.domain.backup import (
    BackupId,
    BackupMetadata,
    BackupSnapshot,
    BackupStatus,
    BackupType,
    RetentionPolicy,
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
            backup_id=bid, backup_type=BackupType.FULL, status=BackupStatus.COMPLETED,
            encrypted=True, compressed=True, checksum="",
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
            backup_id=bid, backup_type=BackupType.FULL, status=BackupStatus.COMPLETED,
            encrypted=True, compressed=True, checksum="",
        )
        repo.find_backup_by_id.return_value = backup
        storage.read.return_value = None
        uc = RestoreBackup(repo, storage, encryption, compression, audit)
        result = uc.execute("bkp-1")
        assert result.status == BackupStatus.FAILED


class TestListBackups:
    def test_list(self, repo) -> None:
        repo.find_all_backups.return_value = [
            BackupMetadata(backup_id=BackupId(value="bkp-1"), backup_type=BackupType.FULL, status=BackupStatus.COMPLETED),
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
            backup_id=BackupId(value="bkp-1"), backup_type=BackupType.FULL, status=BackupStatus.COMPLETED,
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
            backup_id=BackupId(value="bkp-1"), backup_type=BackupType.FULL, status=BackupStatus.COMPLETED,
            encrypted=True, compressed=True,
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
            backup_id=BackupId(value="bkp-1"), backup_type=BackupType.FULL, status=BackupStatus.COMPLETED,
            encrypted=True, compressed=True,
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
        backups = [
            BackupMetadata(backup_id=BackupId(value=f"bkp-{i}"), backup_type=BackupType.FULL, status=BackupStatus.COMPLETED)
            for i in range(5)
        ]
        repo.find_all_backups.return_value = backups
        policy = RetentionPolicy(max_full_backups=2, max_incremental_backups=10)
        uc = CleanupExpiredBackups(repo, storage, audit, policy)
        deleted = uc.execute()
        assert deleted == 3

    def test_cleanup_removes_excess_incremental(self, repo, storage, audit) -> None:
        backups = [
            BackupMetadata(backup_id=BackupId(value=f"bkp-{i}"), backup_type=BackupType.INCREMENTAL, status=BackupStatus.COMPLETED)
            for i in range(5)
        ]
        repo.find_all_backups.return_value = backups
        policy = RetentionPolicy(max_full_backups=10, max_incremental_backups=2)
        uc = CleanupExpiredBackups(repo, storage, audit, policy)
        deleted = uc.execute()
        assert deleted == 3

    def test_cleanup_no_excess(self, repo, storage, audit) -> None:
        backups = [
            BackupMetadata(backup_id=BackupId(value="bkp-1"), backup_type=BackupType.FULL, status=BackupStatus.COMPLETED),
        ]
        repo.find_all_backups.return_value = backups
        uc = CleanupExpiredBackups(repo, storage, audit)
        deleted = uc.execute()
        assert deleted == 0
