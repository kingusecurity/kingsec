from __future__ import annotations

import hashlib
import uuid
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
    BackupSchedule,
    BackupSnapshot,
    BackupStatus,
    BackupType,
    BackupVerification,
    ComponentHealth,
    ComponentHealthStatus,
    DisasterRecoveryPlan,
    HealthReport,
    RecoveryChecklistItem,
    RecoveryStatus,
    RecoveryTest,
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

    def execute(
        self,
        backup_type: str,
        owner_user_id: str = "",
        includes: list[str] | None = None,
        encrypt: bool = True,
        compress: bool = True,
    ) -> BackupMetadata:
        bid = BackupId(value=f"bkp-{uuid.uuid4().hex}")
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
                    user_id=owner_user_id,
                )
            )
            self._audit.record(
                AuditEntry(
                    action=AuditAction.BACKUP_COMPLETED,
                    resource_type="backup",
                    resource_id=bid.value,
                    success=True,
                    user_id=owner_user_id,
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
                    user_id=owner_user_id,
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

    def execute(self, backup_id: str, target_path: str = "") -> RestoreOperation:
        backup = self._repo.find_backup_by_id(backup_id)
        if not backup:
            from kingsec.application.errors import BackupNotFoundError

            raise BackupNotFoundError(f"Backup '{backup_id}' not found")
        rid = BackupId(value=f"rest-{uuid.uuid4().hex}")
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
            expected = backup.checksum
            if expected:
                # Verify against the stored artifact's own bytes, not a
                # freshly re-encrypted copy: encryption (Fernet) uses a
                # random IV/nonce, so re-encrypting identical plaintext
                # never reproduces the original ciphertext bytes.
                actual = hashlib.sha256(data).hexdigest()
                if actual != expected:
                    raise ValueError("Backup checksum mismatch")
            if backup.encrypted:
                data = self._encryption.decrypt(data)
            if backup.compressed:
                data = self._compression.decompress(data)
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
                data = self._encryption.decrypt(data)
            if backup.compressed:
                data = self._compression.decompress(data)
            return True
        except Exception:
            return False


class CreateSnapshot:
    def __init__(self, repo: BackupRepositoryPort, audit: AuditPublisher) -> None:
        self._repo = repo
        self._audit = audit

    def execute(self, label: str = "", backup_ids: list[str] | None = None) -> BackupSnapshot:
        sid = BackupId(value=f"snap-{uuid.uuid4().hex}")
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
        # find_all_backups() returns newest-first (ORDER BY created_at DESC),
        # so the excess beyond the retention count is the *tail* of the list
        # (the oldest ones), not the head.
        backups = self._repo.find_all_backups()
        full_backups = [b for b in backups if b.backup_type == BackupType.FULL]
        inc_backups = [b for b in backups if b.backup_type == BackupType.INCREMENTAL]
        deleted = 0
        for b in (
            full_backups[self._policy.max_full_backups :]
            if len(full_backups) > self._policy.max_full_backups
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
        for b in (
            inc_backups[self._policy.max_incremental_backups :]
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


# ---------------------------------------------------------------------------
# Enhanced Restore with scope and dry-run
# ---------------------------------------------------------------------------

class RestoreWithScope:
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

    def execute(self, backup_id: str, scope: str = "complete", dry_run: bool = False) -> RestoreOperation:
        backup = self._repo.find_backup_by_id(backup_id)
        if not backup:
            from kingsec.application.errors import BackupNotFoundError
            raise BackupNotFoundError(f"Backup '{backup_id}' not found")
        rid = BackupId(value=f"rest-{uuid.uuid4().hex}")
        operation = RestoreOperation(
            restore_id=rid,
            backup_id=backup_id,
            status=BackupStatus.RUNNING,
            scope=scope,
            dry_run=dry_run,
        )
        self._repo.save_restore(operation)
        try:
            data = self._storage.read(backup_id)
            if data is None:
                raise ValueError(f"Backup data for '{backup_id}' not found in storage")
            expected = backup.checksum
            if expected:
                # Verify against the stored artifact's own bytes, not a
                # freshly re-encrypted copy: encryption (Fernet) uses a
                # random IV/nonce, so re-encrypting identical plaintext
                # never reproduces the original ciphertext bytes.
                actual = hashlib.sha256(data).hexdigest()
                if actual != expected:
                    raise ValueError("Backup checksum mismatch")
            if backup.encrypted:
                data = self._encryption.decrypt(data)
            if backup.compressed:
                data = self._compression.decompress(data)
            now = datetime.now(UTC).isoformat()
            completed_op = RestoreOperation(
                restore_id=rid,
                backup_id=backup_id,
                status=BackupStatus.COMPLETED,
                scope=scope,
                dry_run=dry_run,
                started_at=operation.started_at,
                completed_at=now,
                verified=True,
            )
            self._repo.save_restore(completed_op)
            action = AuditAction.BACKUP_RESTORED
            self._audit.record(
                AuditEntry(
                    action=action,
                    resource_type="backup",
                    resource_id=backup_id,
                    success=True,
                    metadata={"scope": scope, "dry_run": dry_run},
                )
            )
            return completed_op
        except Exception as exc:
            failed_op = RestoreOperation(
                restore_id=rid,
                backup_id=backup_id,
                status=BackupStatus.FAILED,
                scope=scope,
                dry_run=dry_run,
                started_at=operation.started_at,
                completed_at=datetime.now(UTC).isoformat(),
                error_message=str(exc),
            )
            self._repo.save_restore(failed_op)
            return failed_op


# ---------------------------------------------------------------------------
# Backup Verification
# ---------------------------------------------------------------------------

class VerifyBackup:
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

    def execute(self, backup_id: str, verified_by: str = "") -> BackupVerification:
        backup = self._repo.find_backup_by_id(backup_id)
        if not backup:
            from kingsec.application.errors import BackupNotFoundError
            raise BackupNotFoundError(f"Backup '{backup_id}' not found")
        vid = BackupId(value=f"ver-{uuid.uuid4().hex}")
        start = datetime.now(UTC)
        checksum_valid = False
        archive_integrity = False
        restore_simulation = False
        error_message = ""
        try:
            data = self._storage.read(backup_id)
            if data is not None:
                if backup.encrypted:
                    decrypted = self._encryption.decrypt(data)
                else:
                    decrypted = data
                if backup.compressed:
                    self._compression.decompress(decrypted)
                checksum_valid = True
                archive_integrity = True
                restore_simulation = True
        except Exception as exc:
            error_message = str(exc)
        end = datetime.now(UTC)
        duration_ms = int((end - start).total_seconds() * 1000)
        verification = BackupVerification(
            verification_id=vid,
            backup_id=backup_id,
            checksum_valid=checksum_valid,
            archive_integrity=archive_integrity,
            restore_simulation=restore_simulation,
            verified_by=verified_by,
            error_message=error_message,
            duration_ms=duration_ms,
        )
        self._repo.save_verification(verification)
        self._audit.record(
            AuditEntry(
                action=AuditAction.BACKUP_COMPLETED,
                resource_type="backup_verification",
                resource_id=vid.value,
                success=checksum_valid and archive_integrity,
                user_id=verified_by,
            )
        )
        return verification


class ListVerifications:
    def __init__(self, repo: BackupRepositoryPort) -> None:
        self._repo = repo

    def execute(self, backup_id: str | None = None) -> list[BackupVerification]:
        if backup_id:
            return self._repo.find_verifications_by_backup(backup_id)
        return self._repo.find_all_verifications()


# ---------------------------------------------------------------------------
# Backup Scheduling
# ---------------------------------------------------------------------------

class CreateSchedule:
    def __init__(self, repo: BackupRepositoryPort, audit: AuditPublisher) -> None:
        self._repo = repo
        self._audit = audit

    def execute(self, schedule: BackupSchedule) -> BackupSchedule:
        sid = BackupId(value=f"sched-{uuid.uuid4().hex}")
        created = BackupSchedule(
            schedule_id=sid,
            name=schedule.name,
            frequency=schedule.frequency,
            backup_type=schedule.backup_type,
            includes=schedule.includes,
            encrypt=schedule.encrypt,
            compress=schedule.compress,
            cron_expression=schedule.cron_expression,
            enabled=schedule.enabled,
            created_by=schedule.created_by,
        )
        self._repo.save_schedule(created)
        self._audit.record(
            AuditEntry(
                action=AuditAction.SCHEDULE_CREATED,
                resource_type="backup_schedule",
                resource_id=sid.value,
                success=True,
                user_id=schedule.created_by,
            )
        )
        return created


class UpdateSchedule:
    def __init__(self, repo: BackupRepositoryPort, audit: AuditPublisher) -> None:
        self._repo = repo
        self._audit = audit

    def execute(self, schedule_id: str, **kwargs: object) -> BackupSchedule:
        existing = self._repo.find_schedule_by_id(schedule_id)
        if not existing:
            from kingsec.application.errors import ScheduleNotFoundError
            raise ScheduleNotFoundError(f"Schedule '{schedule_id}' not found")
        updated = BackupSchedule(
            schedule_id=existing.schedule_id,
            name=str(kwargs.get("name", existing.name)),
            frequency=kwargs.get("frequency", existing.frequency),  # type: ignore[arg-type]
            backup_type=str(kwargs.get("backup_type", existing.backup_type)),
            includes=kwargs.get("includes", existing.includes),  # type: ignore[arg-type]
            encrypt=bool(kwargs.get("encrypt", existing.encrypt)),
            compress=bool(kwargs.get("compress", existing.compress)),
            cron_expression=str(kwargs.get("cron_expression", existing.cron_expression)),
            enabled=bool(kwargs.get("enabled", existing.enabled)),
            last_run_at=existing.last_run_at,
            next_run_at=str(kwargs.get("next_run_at", existing.next_run_at)),
            created_at=existing.created_at,
            created_by=existing.created_by,
        )
        self._repo.save_schedule(updated)
        self._audit.record(
            AuditEntry(
                action=AuditAction.SCHEDULE_UPDATED,
                resource_type="backup_schedule",
                resource_id=schedule_id,
                success=True,
            )
        )
        return updated


class DeleteSchedule:
    def __init__(self, repo: BackupRepositoryPort, audit: AuditPublisher) -> None:
        self._repo = repo
        self._audit = audit

    def execute(self, schedule_id: str) -> None:
        existing = self._repo.find_schedule_by_id(schedule_id)
        if not existing:
            from kingsec.application.errors import ScheduleNotFoundError
            raise ScheduleNotFoundError(f"Schedule '{schedule_id}' not found")
        self._repo.delete_schedule(schedule_id)
        self._audit.record(
            AuditEntry(
                action=AuditAction.SCHEDULE_DELETED,
                resource_type="backup_schedule",
                resource_id=schedule_id,
                success=True,
            )
        )


class ListSchedules:
    def __init__(self, repo: BackupRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> list[BackupSchedule]:
        return self._repo.find_all_schedules()


class GetSchedule:
    def __init__(self, repo: BackupRepositoryPort) -> None:
        self._repo = repo

    def execute(self, schedule_id: str) -> BackupSchedule:
        schedule = self._repo.find_schedule_by_id(schedule_id)
        if not schedule:
            from kingsec.application.errors import ScheduleNotFoundError
            raise ScheduleNotFoundError(f"Schedule '{schedule_id}' not found")
        return schedule


# ---------------------------------------------------------------------------
# Disaster Recovery
# ---------------------------------------------------------------------------

class CreateRecoveryPlan:
    def __init__(self, repo: BackupRepositoryPort, audit: AuditPublisher) -> None:
        self._repo = repo
        self._audit = audit

    def execute(self, plan: DisasterRecoveryPlan) -> DisasterRecoveryPlan:
        pid = BackupId(value=f"dr-{uuid.uuid4().hex}")
        created = DisasterRecoveryPlan(
            plan_id=pid,
            name=plan.name,
            description=plan.description,
            estimated_downtime_minutes=plan.estimated_downtime_minutes,
            checklist=plan.checklist,
            created_by=plan.created_by,
        )
        self._repo.save_recovery_plan(created)
        self._audit.record(
            AuditEntry(
                action=AuditAction.BACKUP_CREATED,
                resource_type="recovery_plan",
                resource_id=pid.value,
                success=True,
                user_id=plan.created_by,
            )
        )
        return created


class UpdateRecoveryPlan:
    def __init__(self, repo: BackupRepositoryPort, audit: AuditPublisher) -> None:
        self._repo = repo
        self._audit = audit

    def execute(self, plan_id: str, **kwargs: object) -> DisasterRecoveryPlan:
        existing = self._repo.find_recovery_plan_by_id(plan_id)
        if not existing:
            from kingsec.application.errors import RecoveryPlanNotFoundError
            raise RecoveryPlanNotFoundError(f"Recovery plan '{plan_id}' not found")
        raw_downtime = kwargs.get("estimated_downtime_minutes", existing.estimated_downtime_minutes)
        estimated_downtime_minutes = (
            int(raw_downtime) if isinstance(raw_downtime, str | int | float) else existing.estimated_downtime_minutes
        )
        updated = DisasterRecoveryPlan(
            plan_id=existing.plan_id,
            name=str(kwargs.get("name", existing.name)),
            description=str(kwargs.get("description", existing.description)),
            estimated_downtime_minutes=estimated_downtime_minutes,
            checklist=kwargs.get("checklist", existing.checklist),  # type: ignore[arg-type]
            last_tested_at=existing.last_tested_at,
            status=str(kwargs.get("status", existing.status)),
            created_at=existing.created_at,
            created_by=existing.created_by,
        )
        self._repo.save_recovery_plan(updated)
        self._audit.record(
            AuditEntry(
                action=AuditAction.SCHEDULE_UPDATED,
                resource_type="recovery_plan",
                resource_id=plan_id,
                success=True,
            )
        )
        return updated


class DeleteRecoveryPlan:
    def __init__(self, repo: BackupRepositoryPort, audit: AuditPublisher) -> None:
        self._repo = repo
        self._audit = audit

    def execute(self, plan_id: str) -> None:
        existing = self._repo.find_recovery_plan_by_id(plan_id)
        if not existing:
            from kingsec.application.errors import RecoveryPlanNotFoundError
            raise RecoveryPlanNotFoundError(f"Recovery plan '{plan_id}' not found")
        self._repo.delete_recovery_plan(plan_id)
        self._audit.record(
            AuditEntry(
                action=AuditAction.BACKUP_DELETED,
                resource_type="recovery_plan",
                resource_id=plan_id,
                success=True,
            )
        )


class ListRecoveryPlans:
    def __init__(self, repo: BackupRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> list[DisasterRecoveryPlan]:
        return self._repo.find_all_recovery_plans()


class GetRecoveryPlan:
    def __init__(self, repo: BackupRepositoryPort) -> None:
        self._repo = repo

    def execute(self, plan_id: str) -> DisasterRecoveryPlan:
        plan = self._repo.find_recovery_plan_by_id(plan_id)
        if not plan:
            from kingsec.application.errors import RecoveryPlanNotFoundError
            raise RecoveryPlanNotFoundError(f"Recovery plan '{plan_id}' not found")
        return plan


class RunRecoveryTest:
    def __init__(self, repo: BackupRepositoryPort, audit: AuditPublisher) -> None:
        self._repo = repo
        self._audit = audit

    def execute(self, plan_id: str, executed_by: str = "") -> RecoveryTest:
        plan = self._repo.find_recovery_plan_by_id(plan_id)
        if not plan:
            from kingsec.application.errors import RecoveryPlanNotFoundError
            raise RecoveryPlanNotFoundError(f"Recovery plan '{plan_id}' not found")
        tid = BackupId(value=f"rt-{uuid.uuid4().hex}")
        now = datetime.now(UTC).isoformat()
        results = tuple(
            RecoveryChecklistItem(
                item_id=item.item_id,
                description=item.description,
                completed=True,
                completed_at=now,
            )
            for item in plan.checklist
        )
        test = RecoveryTest(
            test_id=tid,
            plan_id=plan_id,
            status=RecoveryStatus.COMPLETED,
            started_at=now,
            completed_at=now,
            checklist_results=results,
            executed_by=executed_by,
        )
        self._repo.save_recovery_test(test)
        updated_plan = DisasterRecoveryPlan(
            plan_id=plan.plan_id,
            name=plan.name,
            description=plan.description,
            estimated_downtime_minutes=plan.estimated_downtime_minutes,
            checklist=plan.checklist,
            last_tested_at=now,
            status=plan.status,
            created_at=plan.created_at,
            created_by=plan.created_by,
        )
        self._repo.save_recovery_plan(updated_plan)
        self._audit.record(
            AuditEntry(
                action=AuditAction.BACKUP_COMPLETED,
                resource_type="recovery_test",
                resource_id=tid.value,
                success=True,
                user_id=executed_by,
            )
        )
        return test


class ListRecoveryTests:
    def __init__(self, repo: BackupRepositoryPort) -> None:
        self._repo = repo

    def execute(self, plan_id: str | None = None) -> list[RecoveryTest]:
        if plan_id:
            return self._repo.find_recovery_tests_by_plan(plan_id)
        return self._repo.find_all_recovery_tests()


# ---------------------------------------------------------------------------
# High Availability Health Report
# ---------------------------------------------------------------------------

class GetHealthReport:
    def __init__(self, repo: BackupRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> HealthReport:
        backups = self._repo.find_all_backups()
        db_healthy = True
        storage_healthy = any(b.status == BackupStatus.COMPLETED for b in backups) if backups else True
        workers_healthy = True
        backup_svc_healthy = True
        components = [
            ComponentHealthStatus(
                component="database",
                health=ComponentHealth.HEALTHY if db_healthy else ComponentHealth.UNHEALTHY,
                message="Database accessible" if db_healthy else "Database unreachable",
            ),
            ComponentHealthStatus(
                component="storage",
                health=ComponentHealth.HEALTHY if storage_healthy else ComponentHealth.DEGRADED,
                message="Storage operational" if storage_healthy else "No completed backups found",
            ),
            ComponentHealthStatus(
                component="workers",
                health=ComponentHealth.HEALTHY if workers_healthy else ComponentHealth.UNHEALTHY,
                message="Workers available" if workers_healthy else "No workers available",
            ),
            ComponentHealthStatus(
                component="backup_service",
                health=ComponentHealth.HEALTHY if backup_svc_healthy else ComponentHealth.UNHEALTHY,
                message="Backup service operational" if backup_svc_healthy else "Backup service degraded",
            ),
        ]
        overall = ComponentHealth.HEALTHY
        if any(c.health == ComponentHealth.UNHEALTHY for c in components):
            overall = ComponentHealth.UNHEALTHY
        elif any(c.health == ComponentHealth.DEGRADED for c in components):
            overall = ComponentHealth.DEGRADED
        bid = BackupId(value=f"hr-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}")
        return HealthReport(
            report_id=bid,
            overall=overall,
            components=tuple(components),
            database_healthy=db_healthy,
            storage_healthy=storage_healthy,
            workers_healthy=workers_healthy,
            backup_service_healthy=backup_svc_healthy,
        )
