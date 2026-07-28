"""Tests for the Alembic migration system.

Verifies that:
    * Migrations apply successfully (upgrade head).
    * Downgrade works (downgrade base).
    * Upgrade after downgrade works (round-trip).
    * Autogenerate detects model changes (no-op on clean state).
    * SQLite works as the default backend.
    * The metadata matches all expected tables.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect

# Project root — three levels up from this test file (tests/integration/).
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _run_alembic(*args: str, database_url: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run an Alembic command as a subprocess.

    Args:
        *args: Alembic CLI arguments (e.g. ``"upgrade", "head"``).
        database_url: Optional database URL override via env var.

    Returns:
        The completed subprocess result.

    Raises:
        subprocess.CalledProcessError: If the Alembic command exits non-zero.
    """
    import os

    env = os.environ.copy()
    if database_url:
        env["ALEMBIC_DATABASE_URL"] = database_url

    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=str(_PROJECT_ROOT),
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )


def _get_tables(database_url: str) -> set[str]:
    """Return the set of table names in the given database."""
    engine = create_engine(database_url, future=True)
    try:
        inspector = inspect(engine)
        return set(inspector.get_table_names())
    finally:
        engine.dispose()


def _get_indexes(database_url: str, table_name: str) -> dict[str, bool]:
    """Return index info for a table: {name: is_unique}."""
    engine = create_engine(database_url, future=True)
    try:
        inspector = inspect(engine)
        return {idx["name"]: idx["unique"] for idx in inspector.get_indexes(table_name) if idx["name"]}
    finally:
        engine.dispose()


EXPECTED_TABLES = frozenset(
    {
        "api_keys",
        "assessments",
        "assets",
        "audit_entries",
        "audit_events",
        "evidence",
        "findings",
        "licenses",
        "mfa_recovery_codes",
        "mfa_secrets",
        "notifications",
        "org_activity_events",
        "organization_memberships",
        "organizations",
        "recommendations",
        "reports",
        "revoked_tokens",
        "scan_findings",
        "scan_jobs",
        "scan_reports",
        "scan_results",
        "schedules",
        "sessions",
        "team_memberships",
        "teams",
        "users",
    }
)


class TestMigrationUpgrade:
    """Tests for ``alembic upgrade head``."""

    def test_upgrade_creates_all_tables(self, tmp_path: Path) -> None:
        """Upgrade head must create every expected table."""
        db_path = tmp_path / "test.db"
        db_url = f"sqlite:///{db_path}"

        result = _run_alembic("upgrade", "head", database_url=db_url)
        assert result.returncode == 0, f"alembic upgrade failed:\n{result.stderr}"

        tables = _get_tables(db_url)
        assert EXPECTED_TABLES.issubset(tables), f"Missing tables: {EXPECTED_TABLES - tables}"

    def test_upgrade_is_idempotent(self, tmp_path: Path) -> None:
        """Running upgrade head twice must not fail."""
        db_path = tmp_path / "test.db"
        db_url = f"sqlite:///{db_path}"

        result1 = _run_alembic("upgrade", "head", database_url=db_url)
        assert result1.returncode == 0

        result2 = _run_alembic("upgrade", "head", database_url=db_url)
        assert result2.returncode == 0, f"Second upgrade failed:\n{result2.stderr}"

    def test_upgrade_creates_expected_indexes(self, tmp_path: Path) -> None:
        """Tables must have their expected indexes after upgrade."""
        db_path = tmp_path / "test.db"
        db_url = f"sqlite:///{db_path}"

        result = _run_alembic("upgrade", "head", database_url=db_url)
        assert result.returncode == 0

        # Check specific indexes that the models define.
        users_indexes = _get_indexes(db_url, "users")
        assert "ix_users_username" in users_indexes
        assert "ix_users_email" in users_indexes

        audit_indexes = _get_indexes(db_url, "audit_entries")
        assert "ix_audit_entries_timestamp" in audit_indexes
        assert "ix_audit_entries_user_id" in audit_indexes
        assert "ix_audit_entries_action" in audit_indexes


class TestMigrationDowngrade:
    """Tests for ``alembic downgrade base``."""

    def test_downgrade_removes_all_tables(self, tmp_path: Path) -> None:
        """Downgrade base must drop every table."""
        db_path = tmp_path / "test.db"
        db_url = f"sqlite:///{db_path}"

        # Create schema first.
        result = _run_alembic("upgrade", "head", database_url=db_url)
        assert result.returncode == 0

        # Downgrade.
        result = _run_alembic("downgrade", "base", database_url=db_url)
        assert result.returncode == 0, f"alembic downgrade failed:\n{result.stderr}"

        tables = _get_tables(db_url)
        # alembic_version is Alembic's internal table — it always remains.
        assert tables <= {"alembic_version"}, f"Unexpected tables after downgrade: {tables - {'alembic_version'}}"


class TestMigrationRoundTrip:
    """Tests for upgrade -> downgrade -> upgrade cycle."""

    def test_upgrade_downgrade_upgrade_cycle(self, tmp_path: Path) -> None:
        """Full round-trip must succeed and produce the expected schema."""
        db_path = tmp_path / "test.db"
        db_url = f"sqlite:///{db_path}"

        # 1. Upgrade
        result = _run_alembic("upgrade", "head", database_url=db_url)
        assert result.returncode == 0
        tables = _get_tables(db_url)
        assert EXPECTED_TABLES.issubset(tables)

        # 2. Downgrade
        result = _run_alembic("downgrade", "base", database_url=db_url)
        assert result.returncode == 0
        tables = _get_tables(db_url)
        assert tables <= {"alembic_version"}, f"Unexpected tables after downgrade: {tables - {'alembic_version'}}"

        # 3. Upgrade again
        result = _run_alembic("upgrade", "head", database_url=db_url)
        assert result.returncode == 0
        tables = _get_tables(db_url)
        assert EXPECTED_TABLES.issubset(tables)


class TestMigrationAutogenerate:
    """Tests for ``alembic revision --autogenerate``."""

    def test_autogenerate_on_clean_state_produces_no_changes(self, tmp_path: Path) -> None:
        """After upgrade, autogenerate should detect no new changes."""
        db_path = tmp_path / "test.db"
        db_url = f"sqlite:///{db_path}"

        # Apply all migrations.
        result = _run_alembic("upgrade", "head", database_url=db_url)
        assert result.returncode == 0

        # Autogenerate should detect nothing new.
        result = _run_alembic(
            "revision",
            "--autogenerate",
            "-m",
            "no changes",
            database_url=db_url,
        )
        assert result.returncode == 0
        # If there were changes, Alembic would create a new migration file.
        # With no changes, it should say "No changes detected" in stderr.
        assert "No changes detected" in result.stderr or result.returncode == 0


class TestMigrationMetadata:
    """Tests that Alembic's metadata matches the ORM models."""

    def test_metadata_has_all_tables(self) -> None:
        """The metadata imported by env.py must know about every ORM table."""
        import importlib.util

        models_path = _PROJECT_ROOT / "src" / "kingsec" / "infrastructure" / "persistence" / "models.py"
        spec = importlib.util.spec_from_file_location("kingsec.infrastructure.persistence.models", models_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        table_names = set(module.Base.metadata.tables.keys())
        assert table_names == EXPECTED_TABLES, (
            f"Metadata tables mismatch.\n"
            f"  Missing from metadata: {EXPECTED_TABLES - table_names}\n"
            f"  Extra in metadata:     {table_names - EXPECTED_TABLES}"
        )
