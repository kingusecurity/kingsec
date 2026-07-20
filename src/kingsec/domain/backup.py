"""Backup domain model: backup types, backups, and snapshots."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class BackupType(StrEnum):
    FULL = "full"
    INCREMENTAL = "incremental"
    SNAPSHOT = "snapshot"


class BackupStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RESTORING = "restoring"


@dataclass(frozen=True)
class BackupId:
    value: str

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class BackupMetadata:
    backup_id: BackupId
    backup_type: BackupType
    status: BackupStatus
    size_bytes: int = 0
    compressed_size_bytes: int = 0
    checksum: str = ""
    encrypted: bool = False
    compressed: bool = False
    file_path: str = ""
    includes: tuple[str, ...] = ()
    owner_user_id: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    completed_at: str = ""
    retention_days: int = 30
    error_message: str = ""


@dataclass(frozen=True)
class BackupSnapshot:
    snapshot_id: BackupId
    backup_ids: tuple[str, ...] = ()
    label: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    size_bytes: int = 0


@dataclass(frozen=True)
class RestoreOperation:
    restore_id: BackupId
    backup_id: str
    status: BackupStatus
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    completed_at: str = ""
    error_message: str = ""
    verified: bool = False
    target_path: str = ""


@dataclass(frozen=True)
class RetentionPolicy:
    max_full_backups: int = 7
    max_incremental_backups: int = 30
    max_snapshots: int = 10
    retention_days: int = 90
