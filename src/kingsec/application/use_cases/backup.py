from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from kingsec.application.ports.outbound import (
    BackupCompressionPort,
    BackupEncryptionPort,
    BackupRepositoryPort,
    BackupStoragePort,
)
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.backup import (
    BackupId,
    BackupMetadata,
    BackupSnapshot,
    BackupStatus,
    BackupType,
    RestoreOperation,
    RetentionPolicy,
)


class CreateBackup:
    def __init__(
        self,
        repo: BackupRepositoryPort,
        storage: BackupStoragePort,
        encryption: BackupEncryptionPort,
        compression: BackupCompressionPort,
        audit: AuditPublisher,
    ) -> None:
        self._repo = repo
        self._storage = storage
        self._encryption = encryption
        self._compression = compression
        self._audit = audit
        self._counter = 0

    def execute(
        self,
        backup_type: str,
        owner_user_id: str = "",
        includes: list[str] | None = None,
        encrypt: bool = True,
        compress: bool = True,
    ) -> BackupMetadata:
        self._counter += 1
        bid = BackupId(value=f"bkp-{self._counter}")
        btype = BackupType.FULL
        for t in BackupType:
            if t.value == backup_type.lower():
                btype = t
                break
        backup = BackupMetadata(
            backup_id=bid,
            backup_type=btype,
            status=BackupStatus.RUNNING,
            includes=tuple(includes or []),
            owner_user_id=owner_user_id,
        )
        self._repo.save_backup(backup)
        try:
            data = f"backup-data-{bid.value}".encode()
            if compress:
                data = self._compression.compress(data)
            if encrypt:
                data = self._encryption.encrypt(data)
            checksum = hashlib.sha256(data).hexdigest()
            file_path = self._storage.write(bid.value, data)
            now = datetime.now(UTC).isoformat()
            completed = BackupMetadata(
                backup_id=bid,
                backup_type=btype,
                status=BackupStatus.COMPLETED,
                size_bytes=len(data),
                compressed_size_bytes=len(data) if compress else 0,
                checksum=checksum,
                encrypted=encrypt,
                compressed=compress,
                file_path=file_path,
                includes=tuple(includes or []),
                owner_user_id=owner_user_id,
                created_at=backup.created_at,
                completed_at=now,
            )
            self._repo.save_backup(completed)
            self._audit.record(
                AuditEntry(
                    action=AuditAction.BACKUP_CREATED,
                    resource_type="backup",
                    resource_id=bid.value,
                    success=True,
                    username=owner_user_id,
                )
            )
            self._audit.record(
                AuditEntry(
                    action=AuditAction.BACKUP_COMPLETED,
                    resource_type="backup",
                    resource_id=bid.value,
                    success=True,
                    username=owner_user_id,
                )
            )
            return completed
        except Exception as exc:
            failed = BackupMetadata(
                backup_id=bid,
                backup_type=btype,
                status=BackupStatus.FAILED,
                error_message=str(exc),
                owner_user_id=owner_user_id,
            )
            self._repo.save_backup(failed)
            self._audit.record(
                AuditEntry(
                    action=AuditAction.BACKUP_FAILED,
                    resource_type="backup",
                    resource_id=bid.value,
                    success=False,
                    reason=str(exc),
                    username=owner_user_id,
                )
            )
            return failed


class RestoreBackup:
    def __init__(
        self,
        repo: BackupRepositoryPort,
        storage: BackupStoragePort,
        encryption: BackupEncryptionPort,
        compression: BackupCompressionPort,
        audit: AuditPublisher,
    ) -> None:
        self._repo = repo
        self._storage = storage
        self._encryption = encryption
        self._compression = compression
        self._audit = audit
        self._counter = 0

    def execute(self, backup_id: str, target_path: str = "") -> RestoreOperation:
        backup = self._repo.find_backup_by_id(backup_id)
        if not backup:
            from kingsec.application.errors import BackupNotFoundError

            raise BackupNotFoundError(f"Backup '{backup_id}' not found")
        self._counter += 1
        rid = BackupId(value=f"rest-{self._counter}")
        operation = RestoreOperation(
            restore_id=rid,
            backup_id=backup_id,
            status=BackupStatus.RESTORING,
            target_path=target_path,
        )
        self._repo.save_restore(operation)
        try:
            data = self._storage.read(backup_id)
            if data is None:
                raise ValueError(f"Backup data for '{backup_id}' not found in storage")
            if backup.encrypted:
                data = self._encryption.decrypt(data)
            if backup.compressed:
                data = self._compression.decompress(data)
            expected = backup.checksum
            if expected:
                re_encoded = data
                if backup.compressed:
                    re_encoded = self._compression.compress(re_encoded)
                if backup.encrypted:
                    re_encoded = self._encryption.encrypt(re_encoded)
                actual = hashlib.sha256(re_encoded).hexdigest()
                if actual != expected:
                    raise ValueError("Backup checksum mismatch")
            now = datetime.now(UTC).isoformat()
            completed_op = RestoreOperation(
                restore_id=rid,
                backup_id=backup_id,
                status=BackupStatus.COMPLETED,
                started_at=operation.started_at,
                completed_at=now,
                verified=False,
                target_path=target_path,
            )
            self._repo.save_restore(completed_op)
            self._audit.record(
                AuditEntry(
                    action=AuditAction.BACKUP_RESTORED,
                    resource_type="backup",
                    resource_id=backup_id,
                    success=True,
                )
            )
            return completed_op
        except Exception as exc:
            failed_op = RestoreOperation(
                restore_id=rid,
                backup_id=backup_id,
                status=BackupStatus.FAILED,
                started_at=operation.started_at,
                completed_at=datetime.now(UTC).isoformat(),
                error_message=str(exc),
                target_path=target_path,
            )
            self._repo.save_restore(failed_op)
            return failed_op


class ListBackups:
    def __init__(self, repo: BackupRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> list[BackupMetadata]:
        return self._repo.find_all_backups()


class DeleteBackup:
    def __init__(self, repo: BackupRepositoryPort, storage: BackupStoragePort, audit: AuditPublisher) -> None:
        self._repo = repo
        self._storage = storage
        self._audit = audit

    def execute(self, backup_id: str) -> None:
        backup = self._repo.find_backup_by_id(backup_id)
        if not backup:
            from kingsec.application.errors import BackupNotFoundError

            raise BackupNotFoundError(f"Backup '{backup_id}' not found")
        self._repo.delete_backup(backup_id)
        self._storage.delete(backup_id)
        self._audit.record(
            AuditEntry(
                action=AuditAction.BACKUP_DELETED,
                resource_type="backup",
                resource_id=backup_id,
                success=True,
            )
        )


class ValidateBackup:
    def __init__(
        self,
        repo: BackupRepositoryPort,
        storage: BackupStoragePort,
        encryption: BackupEncryptionPort,
        compression: BackupCompressionPort,
    ) -> None:
        self._repo = repo
        self._storage = storage
        self._encryption = encryption
        self._compression = compression

    def execute(self, backup_id: str) -> bool:
        backup = self._repo.find_backup_by_id(backup_id)
        if not backup:
            from kingsec.application.errors import BackupNotFoundError

            raise BackupNotFoundError(f"Backup '{backup_id}' not found")
        try:
            data = self._storage.read(backup_id)
            if data is None:
                return False
            if backup.encrypted:
                self._encryption.decrypt(data)
            if backup.compressed:
                self._compression.decompress(data)
            return True
        except Exception:
            return False


class CreateSnapshot:
    def __init__(self, repo: BackupRepositoryPort, audit: AuditPublisher) -> None:
        self._repo = repo
        self._audit = audit
        self._counter = 0

    def execute(self, label: str = "", backup_ids: list[str] | None = None) -> BackupSnapshot:
        self._counter += 1
        sid = BackupId(value=f"snap-{self._counter}")
        snapshot = BackupSnapshot(
            snapshot_id=sid,
            backup_ids=tuple(backup_ids or []),
            label=label,
        )
        self._repo.save_snapshot(snapshot)
        self._audit.record(
            AuditEntry(
                action=AuditAction.SNAPSHOT_CREATED,
                resource_type="snapshot",
                resource_id=sid.value,
                success=True,
            )
        )
        return snapshot


class RestoreSnapshot:
    def __init__(self, repo: BackupRepositoryPort, restore_uc: RestoreBackup, audit: AuditPublisher) -> None:
        self._repo = repo
        self._restore_uc = restore_uc
        self._audit = audit

    def execute(self, snapshot_id: str) -> list[RestoreOperation]:
        snapshot = self._repo.find_snapshot_by_id(snapshot_id)
        if not snapshot:
            from kingsec.application.errors import SnapshotNotFoundError

            raise SnapshotNotFoundError(f"Snapshot '{snapshot_id}' not found")
        operations: list[RestoreOperation] = []
        for bid in snapshot.backup_ids:
            op = self._restore_uc.execute(bid)
            operations.append(op)
        self._audit.record(
            AuditEntry(
                action=AuditAction.SNAPSHOT_RESTORED,
                resource_type="snapshot",
                resource_id=snapshot_id,
                success=True,
            )
        )
        return operations


class VerifyRestore:
    def __init__(self, repo: BackupRepositoryPort) -> None:
        self._repo = repo

    def execute(self, restore_id: str) -> bool:
        operation = self._repo.find_restore_by_id(restore_id)
        if not operation:
            from kingsec.application.errors import RestoreNotFoundError

            raise RestoreNotFoundError(f"Restore operation '{restore_id}' not found")
        return operation.status == BackupStatus.COMPLETED and not operation.error_message


class ListSnapshots:
    def __init__(self, repo: BackupRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> list[BackupSnapshot]:
        return self._repo.find_all_snapshots()


class CleanupExpiredBackups:
    def __init__(
        self,
        repo: BackupRepositoryPort,
        storage: BackupStoragePort,
        audit: AuditPublisher,
        policy: RetentionPolicy | None = None,
    ) -> None:
        self._repo = repo
        self._storage = storage
        self._audit = audit
        self._policy = policy or RetentionPolicy()

    def execute(self) -> int:
        datetime.now(UTC)
        backups = self._repo.find_all_backups()
        full_backups = [b for b in backups if b.backup_type == BackupType.FULL]
        inc_backups = [b for b in backups if b.backup_type == BackupType.INCREMENTAL]
        deleted = 0
        for b in (
            full_backups[: -self._policy.max_full_backups] if len(full_backups) > self._policy.max_full_backups else []
        ):
            self._repo.delete_backup(b.backup_id.value)
            self._storage.delete(b.backup_id.value)
            self._audit.record(
                AuditEntry(
                    action=AuditAction.BACKUP_DELETED,
                    resource_type="backup",
                    resource_id=b.backup_id.value,
                    success=True,
                    reason="retention policy",
                )
            )
            deleted += 1
        for b in (
            inc_backups[: -self._policy.max_incremental_backups]
            if len(inc_backups) > self._policy.max_incremental_backups
            else []
        ):
            self._repo.delete_backup(b.backup_id.value)
            self._storage.delete(b.backup_id.value)
            self._audit.record(
                AuditEntry(
                    action=AuditAction.BACKUP_DELETED,
                    resource_type="backup",
                    resource_id=b.backup_id.value,
                    success=True,
                    reason="retention policy",
                )
            )
            deleted += 1
        return deleted
