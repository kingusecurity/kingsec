"""Backup domain model: backup types, backups, snapshots, schedules, verification, DR, HA."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class BackupType(StrEnum):
    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"
    SNAPSHOT = "snapshot"


class BackupStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RESTORING = "restoring"
    CANCELLED = "cancelled"


class BackupStorageType(StrEnum):
    LOCAL = "local"
    NETWORK_SHARE = "network_share"
    S3 = "s3"
    AZURE_BLOB = "azure_blob"
    GCS = "gcs"


class CompressionFormat(StrEnum):
    ZIP = "zip"
    TAR_GZ = "tar_gz"


class ScheduleFrequency(StrEnum):
    MANUAL = "manual"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CRON = "cron"


class RestoreScope(StrEnum):
    DATABASE = "database"
    CONFIGURATION = "configuration"
    REPORTS = "reports"
    ASSESSMENTS = "assessments"
    FILES = "files"
    LICENSES = "licenses"
    ORGANIZATIONS = "organizations"
    USERS = "users"
    AUDIT_LOGS = "audit_logs"
    SETTINGS = "settings"
    COMPLETE = "complete"


class RecoveryStatus(StrEnum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    TESTING = "testing"


class ComponentHealth(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BackupId:
    value: str

    def __str__(self) -> str:
        return self.value


# ---------------------------------------------------------------------------
# Core backup entities
# ---------------------------------------------------------------------------

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
    storage_type: str = "local"
    compression_format: str = "zip"


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
    scope: str = "complete"
    dry_run: bool = False
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
    retention_by_count: bool = True
    retention_by_age: bool = True


# ---------------------------------------------------------------------------
# Scheduling
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BackupSchedule:
    schedule_id: BackupId
    name: str
    frequency: ScheduleFrequency
    backup_type: str = "full"
    includes: tuple[str, ...] = ()
    encrypt: bool = True
    compress: bool = True
    cron_expression: str = ""
    enabled: bool = True
    last_run_at: str = ""
    next_run_at: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    created_by: str = ""


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BackupVerification:
    verification_id: BackupId
    backup_id: str
    checksum_valid: bool = False
    archive_integrity: bool = False
    restore_simulation: bool = False
    verified_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    verified_by: str = ""
    error_message: str = ""
    duration_ms: int = 0


# ---------------------------------------------------------------------------
# Disaster Recovery
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RecoveryChecklistItem:
    item_id: str
    description: str
    completed: bool = False
    completed_at: str = ""


@dataclass(frozen=True)
class DisasterRecoveryPlan:
    plan_id: BackupId
    name: str
    description: str = ""
    estimated_downtime_minutes: int = 0
    checklist: tuple[RecoveryChecklistItem, ...] = ()
    last_tested_at: str = ""
    status: str = "active"
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    created_by: str = ""


@dataclass(frozen=True)
class RecoveryTest:
    test_id: BackupId
    plan_id: str
    status: RecoveryStatus = RecoveryStatus.NOT_STARTED
    started_at: str = ""
    completed_at: str = ""
    checklist_results: tuple[RecoveryChecklistItem, ...] = ()
    notes: str = ""
    executed_by: str = ""


# ---------------------------------------------------------------------------
# High Availability
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ComponentHealthStatus:
    component: str
    health: ComponentHealth = ComponentHealth.UNKNOWN
    message: str = ""
    checked_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass(frozen=True)
class HealthReport:
    report_id: BackupId
    overall: ComponentHealth = ComponentHealth.UNKNOWN
    components: tuple[ComponentHealthStatus, ...] = ()
    database_healthy: bool = False
    storage_healthy: bool = False
    workers_healthy: bool = False
    backup_service_healthy: bool = False
    generated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
