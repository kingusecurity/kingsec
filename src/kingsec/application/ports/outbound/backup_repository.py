from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.backup import BackupMetadata, BackupSnapshot, RestoreOperation


class BackupRepositoryPort(ABC):
    @abstractmethod
    def save_backup(self, backup: BackupMetadata) -> None:
        ...

    @abstractmethod
    def find_backup_by_id(self, backup_id: str) -> BackupMetadata | None:
        ...

    @abstractmethod
    def find_all_backups(self) -> list[BackupMetadata]:
        ...

    @abstractmethod
    def delete_backup(self, backup_id: str) -> None:
        ...

    @abstractmethod
    def save_snapshot(self, snapshot: BackupSnapshot) -> None:
        ...

    @abstractmethod
    def find_snapshot_by_id(self, snapshot_id: str) -> BackupSnapshot | None:
        ...

    @abstractmethod
    def find_all_snapshots(self) -> list[BackupSnapshot]:
        ...

    @abstractmethod
    def delete_snapshot(self, snapshot_id: str) -> None:
        ...

    @abstractmethod
    def save_restore(self, operation: RestoreOperation) -> None:
        ...

    @abstractmethod
    def find_restore_by_id(self, restore_id: str) -> RestoreOperation | None:
        ...
