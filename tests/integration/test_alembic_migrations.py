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

import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

# Project root — three levels up from this test file (tests/integration/).
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_REAL_ALEMBIC_DIR = _PROJECT_ROOT / "src" / "kingsec" / "alembic"
_REAL_VERSIONS_DIR = _REAL_ALEMBIC_DIR / "versions"


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


def _write_isolated_alembic_ini(tmp_versions_dir: Path, dest: Path) -> Path:
    """Write an Alembic config that can never write a new revision file into
    the real repository.

    ``script_location`` stays pointed at the real, tracked
    ``src/kingsec/alembic`` directory (``env.py`` resolves the ORM metadata
    module via a path relative to its own file, so it must run from its
    real location — see env.py's ``_models_path``). ``version_locations``
    lists both the real (tracked) versions/ directory — so Alembic still
    computes the correct current head/``down_revision`` — and
    ``tmp_versions_dir``. Combined with ``--version-path`` on the
    ``revision --autogenerate`` invocation (which pins exactly which of the
    declared locations a *new* file is written into), this guarantees any
    generated file lands only in ``tmp_versions_dir``, never in the real
    repository, regardless of what Alembic decides to do.

    Verified empirically (Phase 16 report §4): the real repository's
    untracked-file count is asserted unchanged after every use of this
    config in the test below.
    """
    locations = os.pathsep.join([str(_REAL_VERSIONS_DIR), str(tmp_versions_dir)])
    dest.write_text(
        "[alembic]\n"
        f"script_location = {_REAL_ALEMBIC_DIR}\n"
        f"version_locations = {locations}\n"
        f"version_path_separator = {os.pathsep}\n"
        f"prepend_sys_path = {_PROJECT_ROOT / 'src'}\n"
        "file_template = %%(year)d_%%(month).2d_%%(day).2d_%%(hour).2d%%(minute).2d%%(second).2d__%%(slug)s\n"
        "\n"
        "[loggers]\n"
        "keys = root\n"
        "\n"
        "[handlers]\n"
        "keys = console\n"
        "\n"
        "[formatters]\n"
        "keys = generic\n"
        "\n"
        "[logger_root]\n"
        "level = WARN\n"
        "handlers = console\n"
        "qualname =\n"
        "\n"
        "[handler_console]\n"
        "class = StreamHandler\n"
        "args = (sys.stderr,)\n"
        "level = NOTSET\n"
        "formatter = generic\n"
        "\n"
        "[formatter_generic]\n"
        "format = %(levelname)-5.5s [%(name)s] %(message)s\n"
        "datefmt = %H:%M:%S\n",
        encoding="utf-8",
    )
    return dest


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
        "account_links",
        "account_lockouts",
        "ai_provider_config",
        "api_keys",
        "assessments",
        "asset_history",
        "asset_relationships",
        "asset_tags",
        "asset_technologies",
        "assets",
        "audit_entries",
        "audit_events",
        "copilot_conversations",
        "cve_entries",
        "dead_letter_entries",
        "evidence",
        "execution_history",
        "exposure_history",
        "exposures",
        "findings",
        "identity_providers",
        "investigation_notes",
        "job_leases",
        "job_queue_entries",
        "licenses",
        "mfa_recovery_codes",
        "mfa_secrets",
        "monitor_alerts",
        "monitor_events",
        "monitor_rules",
        "notifications",
        "org_activity_events",
        "organization_memberships",
        "organizations",
        "playbooks",
        "plugin_sdk_manifests",
        "recommendations",
        "reports",
        "revoked_tokens",
        "scan_findings",
        "scan_jobs",
        "scan_reports",
        "scan_results",
        "schedules",
        "sessions",
        "sso_sessions",
        "team_memberships",
        "teams",
        "threat_feeds",
        "users",
        "workers",
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

    @pytest.mark.xfail(
        reason=(
            "Phase 16: this assertion is now correct and was never able to "
            "fail before (see docstring) — it just found a genuine, "
            "pre-existing schema drift that predates this fix: the tracked "
            "migration chain (head d1e2f3a4b5c6) is missing a real revision "
            "for a batch of index renames "
            "(ix_account_links_provider -> ix_account_links_provider_id, "
            "and 9 more across asset_history, asset_relationships, "
            "cve_entries, dead_letter_entries, exposures, "
            "identity_providers, job_leases, job_queue_entries, "
            "sso_sessions) that models.py already reflects. This exact diff "
            "is what the very first untracked *__no_changes.py file "
            "captured back on 2026-08-19 (Phase 15 report §2) — it has "
            "been silently true ever since, masked only by the no-op "
            "assertion this phase repairs. Writing the missing migration "
            "is a schema change, outside this phase's scope (stop the "
            "generator, fix the assertion, make packaging deterministic, "
            "remove pollution) — see Phase 16 report §3.2 and §12. "
            "strict=True: this must start failing (not merely passing) the "
            "moment a real migration closes the drift, so this marker gets "
            "removed rather than forgotten."
        ),
        strict=True,
    )
    def test_autogenerate_on_clean_state_produces_no_changes(self, tmp_path: Path) -> None:
        """After upgrade, autogenerate against an up-to-date database must
        write no new revision file anywhere — not in a scratch directory,
        and never in the real, tracked ``versions/`` directory.

        Phase 16: the original version of this test used
        ``assert "No changes detected" in result.stderr or result.returncode == 0``
        — a no-op, since ``alembic revision`` returns 0 whether or not it
        wrote a file, so the right-hand side was always true and this test
        could never fail. It also ran against the repository's real
        ``alembic.ini``, whose ``script_location`` is the real, tracked
        ``src/kingsec/alembic`` — so autogenerate's file (Alembic always
        writes one, even for a genuinely empty diff, unless suppressed —
        see ``env.py``'s ``_skip_empty_autogenerate_revision``) landed
        directly in the repository on every run. That is the exact
        mechanism behind this project's untracked ``*__no_changes.py``
        accumulation (Phase 15 §2), confirmed by this repository's own git
        history to have once stranded a real database (Phase 15 §3.1/§3.2).

        This version fixes both defects together: it isolates the file's
        possible destination entirely away from the real repository
        (``_write_isolated_alembic_ini``, defence layer 1), and it asserts
        the thing the test's name has always claimed — that a clean state
        produces literally no new file (layer 2, backed by env.py's
        directive-suppression hook). Both are required: without the
        isolation, a real diff (a bug this test SHOULD catch) would still
        write into the repository even after the assertion is fixed;
        without the assertion fix, an accidentally-reintroduced diff would
        pass silently again exactly as it did before.
        """
        db_path = tmp_path / "test.db"
        db_url = f"sqlite:///{db_path}"
        tmp_versions_dir = tmp_path / "versions"
        tmp_versions_dir.mkdir()
        isolated_ini = _write_isolated_alembic_ini(tmp_versions_dir, tmp_path / "isolated_alembic.ini")

        real_versions_before = set(_REAL_VERSIONS_DIR.glob("*.py"))

        # Apply all migrations (through the isolated config, so this run's
        # own alembic_version bookkeeping is consistent with what follows).
        result = _run_alembic("-c", str(isolated_ini), "upgrade", "head", database_url=db_url)
        assert result.returncode == 0, result.stderr

        # Autogenerate against a database that exactly matches the ORM
        # metadata must produce no file at all.
        result = _run_alembic(
            "-c",
            str(isolated_ini),
            "revision",
            "--autogenerate",
            "-m",
            "no changes",
            "--version-path",
            str(tmp_versions_dir),
            database_url=db_url,
        )
        assert result.returncode == 0, result.stderr

        tmp_files_after = set(tmp_versions_dir.glob("*.py"))
        assert not tmp_files_after, (
            "autogenerate against an up-to-date database wrote a new "
            f"revision file: {[p.name for p in tmp_files_after]} — this "
            "means the ORM metadata (models.py) and the migration chain "
            "(versions/) have drifted and a real migration is needed."
        )

        # Defence layer 1, verified directly: nothing landed in the real,
        # tracked directory either, independent of the assertion above.
        real_versions_after = set(_REAL_VERSIONS_DIR.glob("*.py"))
        assert real_versions_after == real_versions_before, (
            "autogenerate wrote into the real repository versions/ "
            f"directory: {real_versions_after - real_versions_before}"
        )


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
