from __future__ import annotations

from kingsec.application.ports.backup_service import BackupServicePort
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
    ListSnapshots,
    RestoreBackup,
    RestoreSnapshot,
    ValidateBackup,
    VerifyRestore,
)
from kingsec.domain.backup import BackupId, BackupMetadata, BackupSnapshot, BackupStatus, RestoreOperation, RetentionPolicy


class BackupService(BackupServicePort):
    def __init__(self, repo: BackupRepositoryPort, storage: BackupStoragePort,
                 encryption: BackupEncryptionPort, compression: BackupCompressionPort,
                 audit: AuditPublisher,
                 policy: RetentionPolicy | None = None) -> None:
        self._create_uc = CreateBackup(repo, storage, encryption, compression, audit)
        self._restore_uc = RestoreBackup(repo, storage, encryption, compression, audit)
        self._list_uc = ListBackups(repo)
        self._delete_uc = DeleteBackup(repo, storage, audit)
        self._validate_uc = ValidateBackup(repo, storage, encryption, compression)
        self._create_snap_uc = CreateSnapshot(repo, audit)
        self._list_snap_uc = ListSnapshots(repo)
        self._restore_snap_uc = RestoreSnapshot(repo, self._restore_uc, audit)
        self._verify_uc = VerifyRestore(repo)
        self._cleanup_uc = CleanupExpiredBackups(repo, storage, audit, policy)

    def create_backup(self, backup_type: str, owner_user_id: str = "",
                      includes: list[str] | None = None,
                      encrypt: bool = True,
                      compress: bool = True) -> BackupMetadata:
        return self._create_uc.execute(backup_type, owner_user_id, includes, encrypt, compress)

    def restore_backup(self, backup_id: str, target_path: str = "") -> RestoreOperation:
        return self._restore_uc.execute(backup_id, target_path)

    def list_backups(self) -> list[BackupMetadata]:
        return self._list_uc.execute()

    def delete_backup(self, backup_id: str) -> None:
        self._delete_uc.execute(backup_id)

    def validate_backup(self, backup_id: str) -> bool:
        return self._validate_uc.execute(backup_id)

    def create_snapshot(self, label: str = "",
                        backup_ids: list[str] | None = None) -> BackupSnapshot:
        return self._create_snap_uc.execute(label, backup_ids)

    def restore_snapshot(self, snapshot_id: str) -> RestoreOperation:
        ops = self._restore_snap_uc.execute(snapshot_id)
        return ops[0] if ops else RestoreOperation(
            restore_id=BackupId(value=""),
            backup_id="",
            status=BackupStatus.FAILED,
        )

    def verify_restore(self, restore_id: str) -> bool:
        return self._verify_uc.execute(restore_id)

    def cleanup_expired(self) -> int:
        return self._cleanup_uc.execute()

    def list_snapshots(self) -> list[BackupSnapshot]:
        return self._list_snap_uc.execute()
