from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.backup import BackupMetadata, BackupSnapshot, RestoreOperation


class BackupServicePort(ABC):
    @abstractmethod
    def create_backup(
        self,
        backup_type: str,
        owner_user_id: str = "",
        includes: list[str] | None = None,
        encrypt: bool = True,
        compress: bool = True,
    ) -> BackupMetadata: ...

    @abstractmethod
    def restore_backup(self, backup_id: str, target_path: str = "") -> RestoreOperation: ...

    @abstractmethod
    def list_backups(self) -> list[BackupMetadata]: ...

    @abstractmethod
    def delete_backup(self, backup_id: str) -> None: ...

    @abstractmethod
    def validate_backup(self, backup_id: str) -> bool: ...

    @abstractmethod
    def create_snapshot(self, label: str = "", backup_ids: list[str] | None = None) -> BackupSnapshot: ...

    @abstractmethod
    def restore_snapshot(self, snapshot_id: str) -> RestoreOperation: ...

    @abstractmethod
    def verify_restore(self, restore_id: str) -> bool: ...

    @abstractmethod
    def cleanup_expired(self) -> int: ...

    @abstractmethod
    def list_snapshots(self) -> list[BackupSnapshot]: ...
