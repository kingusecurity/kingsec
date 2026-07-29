from __future__ import annotations

import json
from typing import Any

from kingsec.application.ports.outbound import BackupRepositoryPort
from kingsec.domain.backup import (
    BackupId,
    BackupMetadata,
    BackupSchedule,
    BackupSnapshot,
    BackupStatus,
    BackupType,
    BackupVerification,
    DisasterRecoveryPlan,
    RecoveryChecklistItem,
    RecoveryStatus,
    RecoveryTest,
    RestoreOperation,
)


class InMemoryBackupRepository(BackupRepositoryPort):
    def __init__(self) -> None:
        self._backups: dict[str, BackupMetadata] = {}
        self._snapshots: dict[str, BackupSnapshot] = {}
        self._restores: dict[str, RestoreOperation] = {}
        self._schedules: dict[str, BackupSchedule] = {}
        self._verifications: dict[str, BackupVerification] = {}
        self._recovery_plans: dict[str, DisasterRecoveryPlan] = {}
        self._recovery_tests: dict[str, RecoveryTest] = {}

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

    def save_schedule(self, schedule: BackupSchedule) -> None:
        self._schedules[schedule.schedule_id.value] = schedule

    def find_schedule_by_id(self, schedule_id: str) -> BackupSchedule | None:
        return self._schedules.get(schedule_id)

    def find_all_schedules(self) -> list[BackupSchedule]:
        return list(self._schedules.values())

    def delete_schedule(self, schedule_id: str) -> None:
        self._schedules.pop(schedule_id, None)

    def save_verification(self, verification: BackupVerification) -> None:
        self._verifications[verification.verification_id.value] = verification

    def find_verification_by_id(self, verification_id: str) -> BackupVerification | None:
        return self._verifications.get(verification_id)

    def find_verifications_by_backup(self, backup_id: str) -> list[BackupVerification]:
        return [v for v in self._verifications.values() if v.backup_id == backup_id]

    def find_all_verifications(self) -> list[BackupVerification]:
        return list(self._verifications.values())

    def save_recovery_plan(self, plan: DisasterRecoveryPlan) -> None:
        self._recovery_plans[plan.plan_id.value] = plan

    def find_recovery_plan_by_id(self, plan_id: str) -> DisasterRecoveryPlan | None:
        return self._recovery_plans.get(plan_id)

    def find_all_recovery_plans(self) -> list[DisasterRecoveryPlan]:
        return list(self._recovery_plans.values())

    def delete_recovery_plan(self, plan_id: str) -> None:
        self._recovery_plans.pop(plan_id, None)

    def save_recovery_test(self, test: RecoveryTest) -> None:
        self._recovery_tests[test.test_id.value] = test

    def find_recovery_test_by_id(self, test_id: str) -> RecoveryTest | None:
        return self._recovery_tests.get(test_id)

    def find_recovery_tests_by_plan(self, plan_id: str) -> list[RecoveryTest]:
        return [t for t in self._recovery_tests.values() if t.plan_id == plan_id]

    def find_all_recovery_tests(self) -> list[RecoveryTest]:
        return list(self._recovery_tests.values())


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

    # --- Schedules ---

    def save_schedule(self, schedule: BackupSchedule) -> None:
        from sqlalchemy import text

        with self._session_factory() as session:
            session.execute(
                text("""
                    INSERT OR REPLACE INTO backup_schedule
                        (schedule_id, name, frequency, backup_type, includes,
                         encrypt, compress, cron_expression, enabled,
                         last_run_at, next_run_at, created_at, created_by)
                    VALUES (:schedule_id, :name, :frequency, :backup_type, :includes,
                         :encrypt, :compress, :cron_expression, :enabled,
                         :last_run_at, :next_run_at, :created_at, :created_by)
                """),
                {
                    "schedule_id": schedule.schedule_id.value,
                    "name": schedule.name,
                    "frequency": schedule.frequency.value if hasattr(schedule.frequency, 'value') else str(schedule.frequency),
                    "backup_type": schedule.backup_type,
                    "includes": json.dumps(list(schedule.includes)),
                    "encrypt": int(schedule.encrypt),
                    "compress": int(schedule.compress),
                    "cron_expression": schedule.cron_expression,
                    "enabled": int(schedule.enabled),
                    "last_run_at": schedule.last_run_at,
                    "next_run_at": schedule.next_run_at,
                    "created_at": schedule.created_at,
                    "created_by": schedule.created_by,
                },
            )
            session.commit()

    def find_schedule_by_id(self, schedule_id: str) -> BackupSchedule | None:
        from sqlalchemy import text

        with self._session_factory() as session:
            row = session.execute(
                text("SELECT * FROM backup_schedule WHERE schedule_id = :sid"),
                {"sid": schedule_id},
            ).fetchone()
            if not row:
                return None
            return self._row_to_schedule(row._mapping)

    def find_all_schedules(self) -> list[BackupSchedule]:
        from sqlalchemy import text

        with self._session_factory() as session:
            rows = session.execute(text("SELECT * FROM backup_schedule ORDER BY created_at DESC")).fetchall()
            return [self._row_to_schedule(r._mapping) for r in rows]

    def delete_schedule(self, schedule_id: str) -> None:
        from sqlalchemy import text

        with self._session_factory() as session:
            session.execute(text("DELETE FROM backup_schedule WHERE schedule_id = :sid"), {"sid": schedule_id})
            session.commit()

    # --- Verifications ---

    def save_verification(self, verification: BackupVerification) -> None:
        from sqlalchemy import text

        with self._session_factory() as session:
            session.execute(
                text("""
                    INSERT OR REPLACE INTO backup_verification
                        (verification_id, backup_id, checksum_valid, archive_integrity,
                         restore_simulation, verified_at, verified_by, error_message, duration_ms)
                    VALUES (:verification_id, :backup_id, :checksum_valid, :archive_integrity,
                         :restore_simulation, :verified_at, :verified_by, :error_message, :duration_ms)
                """),
                {
                    "verification_id": verification.verification_id.value,
                    "backup_id": verification.backup_id,
                    "checksum_valid": int(verification.checksum_valid),
                    "archive_integrity": int(verification.archive_integrity),
                    "restore_simulation": int(verification.restore_simulation),
                    "verified_at": verification.verified_at,
                    "verified_by": verification.verified_by,
                    "error_message": verification.error_message,
                    "duration_ms": verification.duration_ms,
                },
            )
            session.commit()

    def find_verification_by_id(self, verification_id: str) -> BackupVerification | None:
        from sqlalchemy import text

        with self._session_factory() as session:
            row = session.execute(
                text("SELECT * FROM backup_verification WHERE verification_id = :vid"),
                {"vid": verification_id},
            ).fetchone()
            if not row:
                return None
            m = row._mapping
            return BackupVerification(
                verification_id=BackupId(value=m.get("verification_id", "")),
                backup_id=m.get("backup_id", ""),
                checksum_valid=bool(m.get("checksum_valid", 0)),
                archive_integrity=bool(m.get("archive_integrity", 0)),
                restore_simulation=bool(m.get("restore_simulation", 0)),
                verified_at=m.get("verified_at", ""),
                verified_by=m.get("verified_by", ""),
                error_message=m.get("error_message", ""),
                duration_ms=m.get("duration_ms", 0),
            )

    def find_verifications_by_backup(self, backup_id: str) -> list[BackupVerification]:
        from sqlalchemy import text

        with self._session_factory() as session:
            rows = session.execute(
                text("SELECT * FROM backup_verification WHERE backup_id = :bid ORDER BY verified_at DESC"),
                {"bid": backup_id},
            ).fetchall()
            return [self._row_to_verification(r._mapping) for r in rows]

    def find_all_verifications(self) -> list[BackupVerification]:
        from sqlalchemy import text

        with self._session_factory() as session:
            rows = session.execute(text("SELECT * FROM backup_verification ORDER BY verified_at DESC")).fetchall()
            return [self._row_to_verification(r._mapping) for r in rows]

    # --- Recovery Plans ---

    def save_recovery_plan(self, plan: DisasterRecoveryPlan) -> None:
        from sqlalchemy import text

        with self._session_factory() as session:
            checklist_data = json.dumps([{"item_id": c.item_id, "description": c.description, "completed": c.completed} for c in plan.checklist])
            session.execute(
                text("""
                    INSERT OR REPLACE INTO backup_recovery_plan
                        (plan_id, name, description, estimated_downtime_minutes,
                         checklist, last_tested_at, status, created_at, created_by)
                    VALUES (:plan_id, :name, :description, :estimated_downtime_minutes,
                         :checklist, :last_tested_at, :status, :created_at, :created_by)
                """),
                {
                    "plan_id": plan.plan_id.value,
                    "name": plan.name,
                    "description": plan.description,
                    "estimated_downtime_minutes": plan.estimated_downtime_minutes,
                    "checklist": checklist_data,
                    "last_tested_at": plan.last_tested_at,
                    "status": plan.status,
                    "created_at": plan.created_at,
                    "created_by": plan.created_by,
                },
            )
            session.commit()

    def find_recovery_plan_by_id(self, plan_id: str) -> DisasterRecoveryPlan | None:
        from sqlalchemy import text

        with self._session_factory() as session:
            row = session.execute(
                text("SELECT * FROM backup_recovery_plan WHERE plan_id = :pid"),
                {"pid": plan_id},
            ).fetchone()
            if not row:
                return None
            return self._row_to_recovery_plan(row._mapping)

    def find_all_recovery_plans(self) -> list[DisasterRecoveryPlan]:
        from sqlalchemy import text

        with self._session_factory() as session:
            rows = session.execute(text("SELECT * FROM backup_recovery_plan ORDER BY created_at DESC")).fetchall()
            return [self._row_to_recovery_plan(r._mapping) for r in rows]

    def delete_recovery_plan(self, plan_id: str) -> None:
        from sqlalchemy import text

        with self._session_factory() as session:
            session.execute(text("DELETE FROM backup_recovery_plan WHERE plan_id = :pid"), {"pid": plan_id})
            session.commit()

    # --- Recovery Tests ---

    def save_recovery_test(self, test: RecoveryTest) -> None:
        from sqlalchemy import text

        with self._session_factory() as session:
            results_data = json.dumps([{"item_id": c.item_id, "description": c.description, "completed": c.completed} for c in test.checklist_results])
            session.execute(
                text("""
                    INSERT OR REPLACE INTO backup_recovery_test
                        (test_id, plan_id, status, started_at, completed_at,
                         checklist_results, notes, executed_by)
                    VALUES (:test_id, :plan_id, :status, :started_at, :completed_at,
                         :checklist_results, :notes, :executed_by)
                """),
                {
                    "test_id": test.test_id.value,
                    "plan_id": test.plan_id,
                    "status": test.status.value if hasattr(test.status, 'value') else str(test.status),
                    "started_at": test.started_at,
                    "completed_at": test.completed_at,
                    "checklist_results": results_data,
                    "notes": test.notes,
                    "executed_by": test.executed_by,
                },
            )
            session.commit()

    def find_recovery_test_by_id(self, test_id: str) -> RecoveryTest | None:
        from sqlalchemy import text

        with self._session_factory() as session:
            row = session.execute(
                text("SELECT * FROM backup_recovery_test WHERE test_id = :tid"),
                {"tid": test_id},
            ).fetchone()
            if not row:
                return None
            return self._row_to_recovery_test(row._mapping)

    def find_recovery_tests_by_plan(self, plan_id: str) -> list[RecoveryTest]:
        from sqlalchemy import text

        with self._session_factory() as session:
            rows = session.execute(
                text("SELECT * FROM backup_recovery_test WHERE plan_id = :pid ORDER BY started_at DESC"),
                {"pid": plan_id},
            ).fetchall()
            return [self._row_to_recovery_test(r._mapping) for r in rows]

    def find_all_recovery_tests(self) -> list[RecoveryTest]:
        from sqlalchemy import text

        with self._session_factory() as session:
            rows = session.execute(text("SELECT * FROM backup_recovery_test ORDER BY started_at DESC")).fetchall()
            return [self._row_to_recovery_test(r._mapping) for r in rows]

    # --- Helpers ---

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

    def _row_to_schedule(self, row: Any) -> BackupSchedule:
        from kingsec.domain.backup import ScheduleFrequency
        includes_raw = row.get("includes", "[]")
        if isinstance(includes_raw, str):
            try:
                includes = tuple(json.loads(includes_raw))
            except (json.JSONDecodeError, TypeError):
                includes = ()
        else:
            includes = tuple(includes_raw) if includes_raw else ()
        return BackupSchedule(
            schedule_id=BackupId(value=row.get("schedule_id", "")),
            name=row.get("name", ""),
            frequency=ScheduleFrequency(row.get("frequency", "manual")),
            backup_type=row.get("backup_type", "full"),
            includes=includes,
            encrypt=bool(row.get("encrypt", 1)),
            compress=bool(row.get("compress", 1)),
            cron_expression=row.get("cron_expression", ""),
            enabled=bool(row.get("enabled", 1)),
            last_run_at=row.get("last_run_at", ""),
            next_run_at=row.get("next_run_at", ""),
            created_at=row.get("created_at", ""),
            created_by=row.get("created_by", ""),
        )

    def _row_to_verification(self, row: Any) -> BackupVerification:
        return BackupVerification(
            verification_id=BackupId(value=row.get("verification_id", "")),
            backup_id=row.get("backup_id", ""),
            checksum_valid=bool(row.get("checksum_valid", 0)),
            archive_integrity=bool(row.get("archive_integrity", 0)),
            restore_simulation=bool(row.get("restore_simulation", 0)),
            verified_at=row.get("verified_at", ""),
            verified_by=row.get("verified_by", ""),
            error_message=row.get("error_message", ""),
            duration_ms=row.get("duration_ms", 0),
        )

    def _row_to_recovery_plan(self, row: Any) -> DisasterRecoveryPlan:
        checklist_raw = row.get("checklist", "[]")
        if isinstance(checklist_raw, str):
            try:
                items = json.loads(checklist_raw)
                checklist = tuple(RecoveryChecklistItem(**c) for c in items)
            except (json.JSONDecodeError, TypeError):
                checklist = ()
        else:
            checklist = ()
        return DisasterRecoveryPlan(
            plan_id=BackupId(value=row.get("plan_id", "")),
            name=row.get("name", ""),
            description=row.get("description", ""),
            estimated_downtime_minutes=row.get("estimated_downtime_minutes", 0),
            checklist=checklist,
            last_tested_at=row.get("last_tested_at", ""),
            status=row.get("status", "active"),
            created_at=row.get("created_at", ""),
            created_by=row.get("created_by", ""),
        )

    def _row_to_recovery_test(self, row: Any) -> RecoveryTest:
        results_raw = row.get("checklist_results", "[]")
        if isinstance(results_raw, str):
            try:
                items = json.loads(results_raw)
                results = tuple(RecoveryChecklistItem(**c) for c in items)
            except (json.JSONDecodeError, TypeError):
                results = ()
        else:
            results = ()
        return RecoveryTest(
            test_id=BackupId(value=row.get("test_id", "")),
            plan_id=row.get("plan_id", ""),
            status=RecoveryStatus(row.get("status", "not_started")),
            started_at=row.get("started_at", ""),
            completed_at=row.get("completed_at", ""),
            checklist_results=results,
            notes=row.get("notes", ""),
            executed_by=row.get("executed_by", ""),
        )
