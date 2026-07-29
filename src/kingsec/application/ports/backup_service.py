from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.backup import (
    BackupMetadata,
    BackupSchedule,
    BackupSnapshot,
    BackupVerification,
    DisasterRecoveryPlan,
    HealthReport,
    RecoveryTest,
    RestoreOperation,
)


class BackupServicePort(ABC):
    # --- Core backup operations ---

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

    # --- Snapshots ---

    @abstractmethod
    def create_snapshot(self, label: str = "", backup_ids: list[str] | None = None) -> BackupSnapshot: ...

    @abstractmethod
    def restore_snapshot(self, snapshot_id: str) -> RestoreOperation: ...

    @abstractmethod
    def list_snapshots(self) -> list[BackupSnapshot]: ...

    # --- Verification ---

    @abstractmethod
    def verify_backup(self, backup_id: str, verified_by: str = "") -> BackupVerification: ...

    @abstractmethod
    def list_verifications(self, backup_id: str | None = None) -> list[BackupVerification]: ...

    # --- Retention ---

    @abstractmethod
    def cleanup_expired(self) -> int: ...

    @abstractmethod
    def verify_restore(self, restore_id: str) -> bool: ...

    # --- Scheduling ---

    @abstractmethod
    def create_schedule(self, schedule: BackupSchedule) -> BackupSchedule: ...

    @abstractmethod
    def update_schedule(self, schedule_id: str, **kwargs: object) -> BackupSchedule: ...

    @abstractmethod
    def delete_schedule(self, schedule_id: str) -> None: ...

    @abstractmethod
    def list_schedules(self) -> list[BackupSchedule]: ...

    @abstractmethod
    def get_schedule(self, schedule_id: str) -> BackupSchedule: ...

    # --- Disaster Recovery ---

    @abstractmethod
    def create_recovery_plan(self, plan: DisasterRecoveryPlan) -> DisasterRecoveryPlan: ...

    @abstractmethod
    def update_recovery_plan(self, plan_id: str, **kwargs: object) -> DisasterRecoveryPlan: ...

    @abstractmethod
    def delete_recovery_plan(self, plan_id: str) -> None: ...

    @abstractmethod
    def list_recovery_plans(self) -> list[DisasterRecoveryPlan]: ...

    @abstractmethod
    def get_recovery_plan(self, plan_id: str) -> DisasterRecoveryPlan: ...

    @abstractmethod
    def test_recovery(self, plan_id: str, executed_by: str = "") -> RecoveryTest: ...

    @abstractmethod
    def list_recovery_tests(self, plan_id: str | None = None) -> list[RecoveryTest]: ...

    # --- High Availability ---

    @abstractmethod
    def get_health_report(self) -> HealthReport: ...

    # --- Restore with scope & dry-run ---

    @abstractmethod
    def restore_with_scope(
        self,
        backup_id: str,
        scope: str = "complete",
        dry_run: bool = False,
    ) -> RestoreOperation: ...
