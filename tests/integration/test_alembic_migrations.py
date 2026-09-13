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

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

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
        "assessment_concurrency_slots",
        "assessment_executions",
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
        "schedule_occurrences",
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


class TestMigrationWithPopulatedUniqueConstrainedData:
    """Phase 18 regression coverage: migration 91969658a556 adds/changes
    three indexes to ``unique=True`` (``job_leases.job_id``,
    ``cve_entries.cve_code``, ``account_links(provider_id,
    external_user_id)``). Phase 17 verified this migration only against an
    *empty* database — ``CREATE UNIQUE INDEX`` fails if the table already
    holds duplicate values, and an empty table can never surface that.

    Phase 18's investigation found the migration is safe: all three
    columns have been protected by a table-level ``sa.UniqueConstraint``
    since each table's *original* creation migration (2026-07-28/29),
    predating 91969658a556 entirely - confirmed empirically by attempting
    to insert a duplicate at the pre-migration head and getting a real
    ``sqlite3.IntegrityError`` (see the Phase 18 report Sec 3). So no
    duplicate-value migration failure is reachable today.

    This test is the regression guard for that finding: it proves the
    migration succeeds against realistically *populated* (not merely
    empty) versions of all three tables, so a future change that weakens
    or removes one of those underlying UniqueConstraints - the actual
    thing standing between "safe" and "this migration can fail on real
    data" - cannot silently regress this without a test noticing. Phase
    16 demonstrated exactly this risk: the one test positioned to catch a
    real problem had an assertion that could never fail.
    """

    def test_upgrade_succeeds_against_populated_tables(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        db_url = f"sqlite:///{db_path}"

        result = _run_alembic("upgrade", "d1e2f3a4b5c6", database_url=db_url)
        assert result.returncode == 0, result.stderr

        engine = create_engine(db_url, future=True)
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO job_leases (lease_id, job_id, worker_id, acquired_at, expires_at, "
                    "renewed_at, released_at) VALUES ('lease-1', 'job-1', 'worker-1', "
                    "'2026-01-01T00:00:00Z', '2026-01-01T00:02:00Z', '', NULL)"
                )
            )
            conn.execute(
                text(
                    "INSERT INTO cve_entries (id, cve_code, description, severity, exploit_maturity, "
                    "threat_score, exploitability_score, priority_score, is_kev, created_at, updated_at) "
                    "VALUES ('cve-1', 'CVE-2024-0001', '', 'NONE', 'unknown', 0.0, 0.0, 0.0, 0, "
                    "'2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
                )
            )
            conn.execute(
                text(
                    "INSERT INTO account_links (id, user_id, provider_id, external_user_id, "
                    "external_username, external_email, linked_at) VALUES ('link-1', 'user-1', "
                    "'provider-1', 'ext-1', '', '', '2026-01-01T00:00:00Z')"
                )
            )
        engine.dispose()

        result = _run_alembic("upgrade", "head", database_url=db_url)
        assert result.returncode == 0, (
            "migration 91969658a556 failed against populated (non-duplicate) data - "
            f"a UniqueConstraint this test relies on may have been weakened: {result.stderr}"
        )

        job_lease_indexes = _get_indexes(db_url, "job_leases")
        assert job_lease_indexes.get("ix_job_leases_job_id")

        cve_indexes = _get_indexes(db_url, "cve_entries")
        assert cve_indexes.get("ix_cve_entries_cve_code")

        link_indexes = _get_indexes(db_url, "account_links")
        assert link_indexes.get("ix_account_links_provider_user")

        # The pre-existing rows survived the migration untouched.
        engine = create_engine(db_url, future=True)
        with engine.begin() as conn:
            assert conn.execute(text("SELECT job_id FROM job_leases WHERE lease_id = 'lease-1'")).scalar() == "job-1"
            assert conn.execute(text("SELECT cve_code FROM cve_entries WHERE id = 'cve-1'")).scalar() == "CVE-2024-0001"
            assert conn.execute(text("SELECT provider_id FROM account_links WHERE id = 'link-1'")).scalar() == "provider-1"
        engine.dispose()

    def test_upgrade_fails_cleanly_if_duplicates_somehow_exist(self, tmp_path: Path) -> None:
        """Belt-and-braces: even though duplicates cannot reach this point
        through any real application path (Phase 18 Sec 3/4), prove
        directly that IF a duplicate ever did exist at upgrade time, the
        failure is the specific, attributable IntegrityError SQLite raises
        - not a generic, unclear error - so an operator who somehow hits
        this is not left guessing."""
        db_path = tmp_path / "test.db"
        db_url = f"sqlite:///{db_path}"

        result = _run_alembic("upgrade", "d1e2f3a4b5c6", database_url=db_url)
        assert result.returncode == 0, result.stderr

        engine = create_engine(db_url, future=True)
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO job_leases (lease_id, job_id, worker_id, acquired_at, expires_at, "
                    "renewed_at, released_at) VALUES ('lease-1', 'job-DUP', 'worker-1', "
                    "'2026-01-01T00:00:00Z', '2026-01-01T00:02:00Z', '', NULL)"
                )
            )
        engine.dispose()

        # A second row with the same job_id cannot even be inserted - the
        # UniqueConstraint from job_leases' original creation migration
        # (2026_07_29_500000__add_distributed_workers.py) already forbids
        # it, independent of anything 91969658a556 does.
        engine = create_engine(db_url, future=True)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO job_leases (lease_id, job_id, worker_id, acquired_at, expires_at, "
                        "renewed_at, released_at) VALUES ('lease-2', 'job-DUP', 'worker-2', "
                        "'2026-01-01T00:00:01Z', '2026-01-01T00:02:01Z', '', NULL)"
                    )
                )
            raise AssertionError("expected the duplicate insert to be rejected, but it succeeded")
        except IntegrityError as exc:
            assert "job_leases.job_id" in str(exc.orig)
        finally:
            engine.dispose()


class TestMigrationAtomicity:
    """Phase 19 regression coverage: Phase 18 §3 found that a migration
    failing partway leaves already-applied DDL permanently on disk while
    ``alembic_version`` stays at the old revision - a state no revision
    describes. Root cause (Phase 19 §2): pysqlite does not open a
    transaction before DDL statements by default - only before INSERT,
    UPDATE, DELETE, and REPLACE (http://bugs.python.org/issue10740, cited
    verbatim in Alembic's own ``ddl/sqlite.py::SQLiteImpl`` docstring) - so
    CREATE/DROP INDEX commit immediately regardless of what Alembic or
    SQLAlchemy believe they have wrapped. ``env.py`` now sets
    ``isolation_level=None`` (true DBAPI-level autocommit, disabling
    pysqlite's own implicit-BEGIN heuristic entirely) and emits ``BEGIN``
    explicitly via a ``"begin"`` event listener, so SQLite's own
    transactional DDL support - which pysqlite was defeating - is actually
    exercised.

    These tests force two independent failure points inside migration
    91969658a556's ``upgrade()`` and confirm the whole revision rolls back
    as one unit, not just the ``alembic_version`` bookkeeping - the exact
    inverse of Phase 18 §3's demonstration.
    """

    def test_forced_failure_near_end_rolls_back_entire_migration(self, tmp_path: Path) -> None:
        """Pre-create the index 91969658a556 itself creates near the end of
        its op sequence (``ix_sso_sessions_provider_id``, operation 31 of
        32) so upgrade head collides and fails there. Every prior operation
        in the same revision - including the five index changes already
        applied to account_links - must be rolled back too."""
        db_path = tmp_path / "test.db"
        db_url = f"sqlite:///{db_path}"

        result = _run_alembic("upgrade", "d1e2f3a4b5c6", database_url=db_url)
        assert result.returncode == 0, result.stderr

        engine = create_engine(db_url, future=True)
        with engine.begin() as conn:
            conn.execute(text("CREATE INDEX ix_sso_sessions_provider_id ON sso_sessions (provider_id)"))
        engine.dispose()

        account_links_before = _get_indexes(db_url, "account_links")
        sso_sessions_before = _get_indexes(db_url, "sso_sessions")

        result = _run_alembic("upgrade", "head", database_url=db_url)
        assert result.returncode != 0, "expected the pre-created colliding index to fail the migration"
        assert "ix_sso_sessions_provider_id already exists" in result.stderr

        engine = create_engine(db_url, future=True)
        with engine.begin() as conn:
            stamp = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        engine.dispose()
        assert stamp == "d1e2f3a4b5c6", (
            f"alembic_version moved to {stamp!r} despite the migration failing - partial application of a failed revision"
        )

        assert _get_indexes(db_url, "account_links") == account_links_before, (
            "account_links' indexes changed even though the migration failed at "
            "sso_sessions - DDL persisted outside the failed revision's rollback"
        )
        assert _get_indexes(db_url, "sso_sessions") == sso_sessions_before, (
            "sso_sessions' indexes changed even though the migration failed"
        )

    def test_forced_failure_near_start_rolls_back_entire_migration(self, tmp_path: Path) -> None:
        """A second, independent failure point and a different underlying
        SQLite error - DROP of an index that no longer exists, rather than
        CREATE of one that already does - at operation 2 of 32. Proves
        rollback is complete there too, including the single DDL statement
        (operation 1) that already succeeded before the failure. One data
        point is a coincidence."""
        db_path = tmp_path / "test.db"
        db_url = f"sqlite:///{db_path}"

        result = _run_alembic("upgrade", "d1e2f3a4b5c6", database_url=db_url)
        assert result.returncode == 0, result.stderr

        engine = create_engine(db_url, future=True)
        with engine.begin() as conn:
            conn.execute(text("DROP INDEX ix_account_links_user"))
        engine.dispose()

        account_links_before = _get_indexes(db_url, "account_links")

        result = _run_alembic("upgrade", "head", database_url=db_url)
        assert result.returncode != 0, "expected the pre-dropped index to fail the migration"
        assert "no such index: ix_account_links_user" in result.stderr

        engine = create_engine(db_url, future=True)
        with engine.begin() as conn:
            stamp = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        engine.dispose()
        assert stamp == "d1e2f3a4b5c6"

        assert _get_indexes(db_url, "account_links") == account_links_before, (
            "operation 1 (dropping ix_account_links_provider) persisted even "
            "though operation 2 failed in the same revision"
        )

    def test_upgrade_succeeds_cleanly_after_a_rolled_back_failure(self, tmp_path: Path) -> None:
        """Recoverability, not just coherence: once the cause of a forced
        failure is removed, upgrade head must succeed and produce exactly
        the schema 91969658a556 defines - proving the rolled-back database
        is genuinely re-runnable, not merely stuck in a valid-looking dead
        end."""
        db_path = tmp_path / "test.db"
        db_url = f"sqlite:///{db_path}"

        result = _run_alembic("upgrade", "d1e2f3a4b5c6", database_url=db_url)
        assert result.returncode == 0, result.stderr

        engine = create_engine(db_url, future=True)
        with engine.begin() as conn:
            conn.execute(text("CREATE INDEX ix_sso_sessions_provider_id ON sso_sessions (provider_id)"))
        engine.dispose()

        failed = _run_alembic("upgrade", "head", database_url=db_url)
        assert failed.returncode != 0

        engine = create_engine(db_url, future=True)
        with engine.begin() as conn:
            conn.execute(text("DROP INDEX ix_sso_sessions_provider_id"))
        engine.dispose()

        recovered = _run_alembic("upgrade", "head", database_url=db_url)
        assert recovered.returncode == 0, f"upgrade head did not recover cleanly: {recovered.stderr}"

        sso_sessions_indexes = _get_indexes(db_url, "sso_sessions")
        assert "ix_sso_sessions_provider_id" in sso_sessions_indexes
        assert "ix_sso_sessions_user_id" in sso_sessions_indexes

        engine = create_engine(db_url, future=True)
        with engine.begin() as conn:
            stamp = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        engine.dispose()
        # Phase 2A: head moved forward from da4b78614806 to 64e10236c8c1
        # (add_report_assessment_status_and_backfill_scanner_status) - this
        # must track the real head, not remain pinned to whatever revision
        # was head when this test was first written.
        assert stamp == "64e10236c8c1"


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
