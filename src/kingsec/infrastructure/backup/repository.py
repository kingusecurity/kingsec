from __future__ import annotations

from typing import Any

from kingsec.application.ports.outbound import BackupRepositoryPort
from kingsec.domain.backup import (
    BackupId,
    BackupMetadata,
    BackupSnapshot,
    BackupStatus,
    BackupType,
    RestoreOperation,
)


class InMemoryBackupRepository(BackupRepositoryPort):
    def __init__(self) -> None:
        self._backups: dict[str, BackupMetadata] = {}
        self._snapshots: dict[str, BackupSnapshot] = {}
        self._restores: dict[str, RestoreOperation] = {}

    def save_backup(self, backup: BackupMetadata) -> None:
        self._backups[backup.backup_id.value] = backup

    def find_backup_by_id(self, backup_id: str) -> BackupMetadata | None:
        return self._backups.get(backup_id)

    def find_all_backups(self) -> list[BackupMetadata]:
        return list(self._backups.values())

    def delete_backup(self, backup_id: str) -> None:
        self._backups.pop(backup_id, None)

    def save_snapshot(self, snapshot: BackupSnapshot) -> None:
        self._snapshots[snapshot.snapshot_id.value] = snapshot

    def find_snapshot_by_id(self, snapshot_id: str) -> BackupSnapshot | None:
        return self._snapshots.get(snapshot_id)

    def find_all_snapshots(self) -> list[BackupSnapshot]:
        return list(self._snapshots.values())

    def delete_snapshot(self, snapshot_id: str) -> None:
        self._snapshots.pop(snapshot_id, None)

    def save_restore(self, operation: RestoreOperation) -> None:
        self._restores[operation.restore_id.value] = operation

    def find_restore_by_id(self, restore_id: str) -> RestoreOperation | None:
        return self._restores.get(restore_id)


class SQLAlchemyBackupRepository(BackupRepositoryPort):
    def __init__(self, session_factory: Any) -> None:
        self._session_factory = session_factory

    def save_backup(self, backup: BackupMetadata) -> None:
        from sqlalchemy import text
        with self._session_factory() as session:
            session.execute(
                text("""
                    INSERT OR REPLACE INTO scan_backup
                        (backup_id, backup_type, status, size_bytes, checksum,
                         encrypted, compressed, file_path, owner_user_id,
                         created_at, completed_at, error_message)
                    VALUES
                        (:backup_id, :backup_type, :status, :size_bytes, :checksum,
                         :encrypted, :compressed, :file_path, :owner_user_id,
                         :created_at, :completed_at, :error_message)
                """),
                {
                    "backup_id": backup.backup_id.value,
                    "backup_type": backup.backup_type.value,
                    "status": backup.status.value,
                    "size_bytes": backup.size_bytes,
                    "checksum": backup.checksum,
                    "encrypted": int(backup.encrypted),
                    "compressed": int(backup.compressed),
                    "file_path": backup.file_path,
                    "owner_user_id": backup.owner_user_id,
                    "created_at": backup.created_at,
                    "completed_at": backup.completed_at,
                    "error_message": backup.error_message,
                },
            )
            session.commit()

    def find_backup_by_id(self, backup_id: str) -> BackupMetadata | None:
        from sqlalchemy import text
        with self._session_factory() as session:
            row = session.execute(
                text("SELECT * FROM scan_backup WHERE backup_id = :bid"),
                {"bid": backup_id},
            ).fetchone()
            if not row:
                return None
            return self._row_to_backup(row._mapping)

    def find_all_backups(self) -> list[BackupMetadata]:
        from sqlalchemy import text
        with self._session_factory() as session:
            rows = session.execute(text("SELECT * FROM scan_backup ORDER BY created_at DESC")).fetchall()
            return [self._row_to_backup(r._mapping) for r in rows]

    def delete_backup(self, backup_id: str) -> None:
        from sqlalchemy import text
        with self._session_factory() as session:
            session.execute(text("DELETE FROM scan_backup WHERE backup_id = :bid"), {"bid": backup_id})
            session.commit()

    def save_snapshot(self, snapshot: BackupSnapshot) -> None:
        from sqlalchemy import text
        with self._session_factory() as session:
            session.execute(
                text("""
                    INSERT OR REPLACE INTO scan_snapshot
                        (snapshot_id, label, created_at, size_bytes)
                    VALUES (:snapshot_id, :label, :created_at, :size_bytes)
                """),
                {
                    "snapshot_id": snapshot.snapshot_id.value,
                    "label": snapshot.label,
                    "created_at": snapshot.created_at,
                    "size_bytes": snapshot.size_bytes,
                },
            )
            session.commit()

    def find_snapshot_by_id(self, snapshot_id: str) -> BackupSnapshot | None:
        from sqlalchemy import text
        with self._session_factory() as session:
            row = session.execute(
                text("SELECT * FROM scan_snapshot WHERE snapshot_id = :sid"),
                {"sid": snapshot_id},
            ).fetchone()
            if not row:
                return None
            m = row._mapping
            return BackupSnapshot(
                snapshot_id=BackupId(value=m.get("snapshot_id", "")),
                label=m.get("label", ""),
                created_at=m.get("created_at", ""),
                size_bytes=m.get("size_bytes", 0),
            )

    def find_all_snapshots(self) -> list[BackupSnapshot]:
        from sqlalchemy import text
        with self._session_factory() as session:
            rows = session.execute(text("SELECT * FROM scan_snapshot ORDER BY created_at DESC")).fetchall()
            return [
                BackupSnapshot(
                    snapshot_id=BackupId(value=r._mapping.get("snapshot_id", "")),
                    label=r._mapping.get("label", ""),
                    created_at=r._mapping.get("created_at", ""),
                    size_bytes=r._mapping.get("size_bytes", 0),
                )
                for r in rows
            ]

    def delete_snapshot(self, snapshot_id: str) -> None:
        from sqlalchemy import text
        with self._session_factory() as session:
            session.execute(text("DELETE FROM scan_snapshot WHERE snapshot_id = :sid"), {"sid": snapshot_id})
            session.commit()

    def save_restore(self, operation: RestoreOperation) -> None:
        from sqlalchemy import text
        with self._session_factory() as session:
            session.execute(
                text("""
                    INSERT OR REPLACE INTO scan_restore
                        (restore_id, backup_id, status, started_at, completed_at, error_message)
                    VALUES (:restore_id, :backup_id, :status, :started_at, :completed_at, :error_message)
                """),
                {
                    "restore_id": operation.restore_id.value,
                    "backup_id": operation.backup_id,
                    "status": operation.status.value,
                    "started_at": operation.started_at,
                    "completed_at": operation.completed_at,
                    "error_message": operation.error_message,
                },
            )
            session.commit()

    def find_restore_by_id(self, restore_id: str) -> RestoreOperation | None:
        from sqlalchemy import text
        with self._session_factory() as session:
            row = session.execute(
                text("SELECT * FROM scan_restore WHERE restore_id = :rid"),
                {"rid": restore_id},
            ).fetchone()
            if not row:
                return None
            m = row._mapping
            return RestoreOperation(
                restore_id=BackupId(value=m.get("restore_id", "")),
                backup_id=m.get("backup_id", ""),
                status=BackupStatus(m.get("status", "pending")),
                started_at=m.get("started_at", ""),
                completed_at=m.get("completed_at", ""),
                error_message=m.get("error_message", ""),
            )

    def _row_to_backup(self, row: Any) -> BackupMetadata:
        return BackupMetadata(
            backup_id=BackupId(value=row.get("backup_id", "")),
            backup_type=BackupType(row.get("backup_type", "full")),
            status=BackupStatus(row.get("status", "pending")),
            size_bytes=row.get("size_bytes", 0),
            checksum=row.get("checksum", ""),
            encrypted=bool(row.get("encrypted", 0)),
            compressed=bool(row.get("compressed", 0)),
            file_path=row.get("file_path", ""),
            owner_user_id=row.get("owner_user_id", ""),
            created_at=row.get("created_at", ""),
            completed_at=row.get("completed_at", ""),
            error_message=row.get("error_message", ""),
        )
