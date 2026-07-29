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
    CreateRecoveryPlan,
    CreateSchedule,
    CreateSnapshot,
    DeleteBackup,
    DeleteRecoveryPlan,
    DeleteSchedule,
    GetHealthReport,
    GetRecoveryPlan,
    GetSchedule,
    ListBackups,
    ListRecoveryPlans,
    ListRecoveryTests,
    ListSchedules,
    ListSnapshots,
    ListVerifications,
    RestoreBackup,
    RestoreSnapshot,
    RestoreWithScope,
    RunRecoveryTest,
    UpdateRecoveryPlan,
    UpdateSchedule,
    ValidateBackup,
    VerifyBackup,
    VerifyRestore,
)
from kingsec.domain.backup import (
    BackupId,
    BackupMetadata,
    BackupSchedule,
    BackupSnapshot,
    BackupStatus,
    BackupVerification,
    DisasterRecoveryPlan,
    HealthReport,
    RecoveryTest,
    RestoreOperation,
    RetentionPolicy,
)


class BackupService(BackupServicePort):
    def __init__(
        self,
        repo: BackupRepositoryPort,
        storage: BackupStoragePort,
        encryption: BackupEncryptionPort,
        compression: BackupCompressionPort,
        audit: AuditPublisher,
        policy: RetentionPolicy | None = None,
    ) -> None:
        self._create_uc = CreateBackup(repo, storage, encryption, compression, audit)
        self._restore_uc = RestoreBackup(repo, storage, encryption, compression, audit)
        self._restore_scope_uc = RestoreWithScope(repo, storage, encryption, compression, audit)
        self._list_uc = ListBackups(repo)
        self._delete_uc = DeleteBackup(repo, storage, audit)
        self._validate_uc = ValidateBackup(repo, storage, encryption, compression)
        self._create_snap_uc = CreateSnapshot(repo, audit)
        self._list_snap_uc = ListSnapshots(repo)
        self._restore_snap_uc = RestoreSnapshot(repo, self._restore_uc, audit)
        self._verify_uc = VerifyRestore(repo)
        self._cleanup_uc = CleanupExpiredBackups(repo, storage, audit, policy)
        self._verify_backup_uc = VerifyBackup(repo, storage, encryption, compression, audit)
        self._list_verifications_uc = ListVerifications(repo)
        self._create_schedule_uc = CreateSchedule(repo, audit)
        self._update_schedule_uc = UpdateSchedule(repo, audit)
        self._delete_schedule_uc = DeleteSchedule(repo, audit)
        self._list_schedules_uc = ListSchedules(repo)
        self._get_schedule_uc = GetSchedule(repo)
        self._create_recovery_uc = CreateRecoveryPlan(repo, audit)
        self._update_recovery_uc = UpdateRecoveryPlan(repo, audit)
        self._delete_recovery_uc = DeleteRecoveryPlan(repo, audit)
        self._list_recovery_uc = ListRecoveryPlans(repo)
        self._get_recovery_uc = GetRecoveryPlan(repo)
        self._test_recovery_uc = RunRecoveryTest(repo, audit)
        self._list_recovery_tests_uc = ListRecoveryTests(repo)
        self._health_uc = GetHealthReport(repo)

    def create_backup(
        self,
        backup_type: str,
        owner_user_id: str = "",
        includes: list[str] | None = None,
        encrypt: bool = True,
        compress: bool = True,
    ) -> BackupMetadata:
        return self._create_uc.execute(backup_type, owner_user_id, includes, encrypt, compress)

    def restore_backup(self, backup_id: str, target_path: str = "") -> RestoreOperation:
        return self._restore_uc.execute(backup_id, target_path)

    def list_backups(self) -> list[BackupMetadata]:
        return self._list_uc.execute()

    def delete_backup(self, backup_id: str) -> None:
        self._delete_uc.execute(backup_id)

    def validate_backup(self, backup_id: str) -> bool:
        return self._validate_uc.execute(backup_id)

    def create_snapshot(self, label: str = "", backup_ids: list[str] | None = None) -> BackupSnapshot:
        return self._create_snap_uc.execute(label, backup_ids)

    def restore_snapshot(self, snapshot_id: str) -> RestoreOperation:
        ops = self._restore_snap_uc.execute(snapshot_id)
        return (
            ops[0]
            if ops
            else RestoreOperation(
                restore_id=BackupId(value=""),
                backup_id="",
                status=BackupStatus.FAILED,
            )
        )

    def verify_restore(self, restore_id: str) -> bool:
        return self._verify_uc.execute(restore_id)

    def cleanup_expired(self) -> int:
        return self._cleanup_uc.execute()

    def list_snapshots(self) -> list[BackupSnapshot]:
        return self._list_snap_uc.execute()

    def verify_backup(self, backup_id: str, verified_by: str = "") -> BackupVerification:
        return self._verify_backup_uc.execute(backup_id, verified_by)

    def list_verifications(self, backup_id: str | None = None) -> list[BackupVerification]:
        return self._list_verifications_uc.execute(backup_id)

    def create_schedule(self, schedule: BackupSchedule) -> BackupSchedule:
        return self._create_schedule_uc.execute(schedule)

    def update_schedule(self, schedule_id: str, **kwargs: object) -> BackupSchedule:
        return self._update_schedule_uc.execute(schedule_id, **kwargs)

    def delete_schedule(self, schedule_id: str) -> None:
        self._delete_schedule_uc.execute(schedule_id)

    def list_schedules(self) -> list[BackupSchedule]:
        return self._list_schedules_uc.execute()

    def get_schedule(self, schedule_id: str) -> BackupSchedule:
        return self._get_schedule_uc.execute(schedule_id)

    def create_recovery_plan(self, plan: DisasterRecoveryPlan) -> DisasterRecoveryPlan:
        return self._create_recovery_uc.execute(plan)

    def update_recovery_plan(self, plan_id: str, **kwargs: object) -> DisasterRecoveryPlan:
        return self._update_recovery_uc.execute(plan_id, **kwargs)

    def delete_recovery_plan(self, plan_id: str) -> None:
        self._delete_recovery_uc.execute(plan_id)

    def list_recovery_plans(self) -> list[DisasterRecoveryPlan]:
        return self._list_recovery_uc.execute()

    def get_recovery_plan(self, plan_id: str) -> DisasterRecoveryPlan:
        return self._get_recovery_uc.execute(plan_id)

    def test_recovery(self, plan_id: str, executed_by: str = "") -> RecoveryTest:
        return self._test_recovery_uc.execute(plan_id, executed_by)

    def list_recovery_tests(self, plan_id: str | None = None) -> list[RecoveryTest]:
        return self._list_recovery_tests_uc.execute(plan_id)

    def get_health_report(self) -> HealthReport:
        return self._health_uc.execute()

    def restore_with_scope(
        self,
        backup_id: str,
        scope: str = "complete",
        dry_run: bool = False,
    ) -> RestoreOperation:
        return self._restore_scope_uc.execute(backup_id, scope, dry_run)
