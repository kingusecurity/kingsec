"""Ensure backup-related tables exist for raw-SQL repositories."""

from __future__ import annotations

from typing import Any

from sqlalchemy import text

_BACKUP_TABLES = """
CREATE TABLE IF NOT EXISTS scan_backup (
    backup_id TEXT PRIMARY KEY,
    backup_type TEXT NOT NULL DEFAULT 'full',
    status TEXT NOT NULL DEFAULT 'pending',
    size_bytes INTEGER DEFAULT 0,
    checksum TEXT DEFAULT '',
    encrypted INTEGER DEFAULT 0,
    compressed INTEGER DEFAULT 0,
    file_path TEXT DEFAULT '',
    owner_user_id TEXT DEFAULT '',
    created_at TEXT DEFAULT '',
    completed_at TEXT DEFAULT '',
    error_message TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scan_snapshot (
    snapshot_id TEXT PRIMARY KEY,
    label TEXT DEFAULT '',
    created_at TEXT DEFAULT '',
    size_bytes INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_restore (
    restore_id TEXT PRIMARY KEY,
    backup_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    started_at TEXT DEFAULT '',
    completed_at TEXT DEFAULT '',
    error_message TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS backup_schedule (
    schedule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    frequency TEXT NOT NULL DEFAULT 'manual',
    backup_type TEXT DEFAULT 'full',
    includes TEXT DEFAULT '[]',
    encrypt INTEGER DEFAULT 1,
    compress INTEGER DEFAULT 1,
    cron_expression TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    last_run_at TEXT DEFAULT '',
    next_run_at TEXT DEFAULT '',
    created_at TEXT DEFAULT '',
    created_by TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS backup_verification (
    verification_id TEXT PRIMARY KEY,
    backup_id TEXT NOT NULL DEFAULT '',
    checksum_valid INTEGER DEFAULT 0,
    archive_integrity INTEGER DEFAULT 0,
    restore_simulation INTEGER DEFAULT 0,
    verified_at TEXT DEFAULT '',
    verified_by TEXT DEFAULT '',
    error_message TEXT DEFAULT '',
    duration_ms INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS backup_recovery_plan (
    plan_id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    estimated_downtime_minutes INTEGER DEFAULT 0,
    checklist TEXT DEFAULT '[]',
    last_tested_at TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT '',
    created_by TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS backup_recovery_test (
    test_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'not_started',
    started_at TEXT DEFAULT '',
    completed_at TEXT DEFAULT '',
    checklist_results TEXT DEFAULT '[]',
    notes TEXT DEFAULT '',
    executed_by TEXT DEFAULT ''
);
"""


def ensure_backup_tables(session_factory: Any) -> None:
    """Create backup-related tables if they do not already exist."""
    with session_factory() as session:
        for statement in _BACKUP_TABLES.split(";"):
            stmt = statement.strip()
            if stmt:
                session.execute(text(stmt))
        session.commit()
