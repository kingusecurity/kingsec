from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.backup import (
    BackupMetadata,
    BackupSchedule,
    BackupSnapshot,
    BackupVerification,
    DisasterRecoveryPlan,
    RecoveryTest,
    RestoreOperation,
)


class BackupRepositoryPort(ABC):
    # --- Backups ---

    @abstractmethod
    def save_backup(self, backup: BackupMetadata) -> None: ...

    @abstractmethod
    def find_backup_by_id(self, backup_id: str) -> BackupMetadata | None: ...

    @abstractmethod
    def find_all_backups(self) -> list[BackupMetadata]: ...

    @abstractmethod
    def delete_backup(self, backup_id: str) -> None: ...

    # --- Snapshots ---

    @abstractmethod
    def save_snapshot(self, snapshot: BackupSnapshot) -> None: ...

    @abstractmethod
    def find_snapshot_by_id(self, snapshot_id: str) -> BackupSnapshot | None: ...

    @abstractmethod
    def find_all_snapshots(self) -> list[BackupSnapshot]: ...

    @abstractmethod
    def delete_snapshot(self, snapshot_id: str) -> None: ...

    # --- Restore operations ---

    @abstractmethod
    def save_restore(self, operation: RestoreOperation) -> None: ...

    @abstractmethod
    def find_restore_by_id(self, restore_id: str) -> RestoreOperation | None: ...

    # --- Schedules ---

    @abstractmethod
    def save_schedule(self, schedule: BackupSchedule) -> None: ...

    @abstractmethod
    def find_schedule_by_id(self, schedule_id: str) -> BackupSchedule | None: ...

    @abstractmethod
    def find_all_schedules(self) -> list[BackupSchedule]: ...

    @abstractmethod
    def delete_schedule(self, schedule_id: str) -> None: ...

    # --- Verifications ---

    @abstractmethod
    def save_verification(self, verification: BackupVerification) -> None: ...

    @abstractmethod
    def find_verification_by_id(self, verification_id: str) -> BackupVerification | None: ...

    @abstractmethod
    def find_verifications_by_backup(self, backup_id: str) -> list[BackupVerification]: ...

    @abstractmethod
    def find_all_verifications(self) -> list[BackupVerification]: ...

    # --- Disaster Recovery ---

    @abstractmethod
    def save_recovery_plan(self, plan: DisasterRecoveryPlan) -> None: ...

    @abstractmethod
    def find_recovery_plan_by_id(self, plan_id: str) -> DisasterRecoveryPlan | None: ...

    @abstractmethod
    def find_all_recovery_plans(self) -> list[DisasterRecoveryPlan]: ...

    @abstractmethod
    def delete_recovery_plan(self, plan_id: str) -> None: ...

    @abstractmethod
    def save_recovery_test(self, test: RecoveryTest) -> None: ...

    @abstractmethod
    def find_recovery_test_by_id(self, test_id: str) -> RecoveryTest | None: ...

    @abstractmethod
    def find_recovery_tests_by_plan(self, plan_id: str) -> list[RecoveryTest]: ...

    @abstractmethod
    def find_all_recovery_tests(self) -> list[RecoveryTest]: ...
