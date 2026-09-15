"""Integration tests for kingsec-bootstrap (src/kingsec/_bootstrap.py).

Phase 3 (auth hardening): this CLI is now the ONLY way an initial
administrator gets created - self-registration never grants ADMIN again
(see test_register_user.py). Before this phase, _bootstrap.py had ZERO
test coverage at all (confirmed via a repo-wide grep for
"kingsec._bootstrap" across tests/ before writing this file).

Runs _bootstrap_admin() for real against a genuinely Alembic-migrated
SQLite database (subprocess `alembic upgrade head`, not create_schema() -
_bootstrap_admin() itself gates on a real `alembic check`, so a schema-
only database would make every test here exercise the wrong failure
path). Verifies the persisted result by querying the SQLite file
directly, the same PRAGMA/direct-query evidence standard used elsewhere
in this engagement, rather than trusting a second wired application's
own read path to prove what the first one wrote.
"""

from __future__ import annotations

import importlib.resources
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from kingsec._bootstrap import _bootstrap_admin

_TEST_FERNET_KEY = Fernet.generate_key().decode()
_TEST_JWT_SECRET = "test-jwt-secret-" + Fernet.generate_key().decode()
_TEST_PEPPER = "test-pepper-" + Fernet.generate_key().decode()


@pytest.fixture
def migrated_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A tmp_path data directory with a REAL, Alembic-migrated database -
    the same env vars test_composition.py's wired_app fixture uses, plus
    a real `alembic upgrade head` subprocess run (not create_schema()),
    since _bootstrap_admin() itself gates on `alembic check` succeeding.
    """
    monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KINGSEC_SECRETS__ENCRYPTION_KEY", _TEST_FERNET_KEY)
    monkeypatch.setenv("KINGSEC_JWT__SECRET_KEY", _TEST_JWT_SECRET)
    monkeypatch.setenv("KINGSEC_SECRETS__API_KEY_PEPPER", _TEST_PEPPER)

    config_path = str(importlib.resources.files("kingsec.alembic").joinpath("alembic.ini"))
    alembic_dir = Path(config_path).parent
    result = subprocess.run(  # nosec B603 — fixed argv, no shell
        [sys.executable, "-m", "alembic", "-c", config_path, "upgrade", "head"],
        cwd=str(alembic_dir),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"migration setup failed: {result.stderr}"
    return tmp_path


def _query_one(db_path: Path, sql: str, params: tuple = ()) -> tuple | None:
    # Read-only URI connection - never a plain sqlite3.connect(path), which
    # can create -wal/-shm files as a side effect of opening even for a read.
    conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        return conn.execute(sql, params).fetchone()
    finally:
        conn.close()


class TestBootstrapAdminCreation:
    def test_creates_admin_and_records_a_findable_audit_entry(self, migrated_data_dir: Path) -> None:
        """Closes both Q6 audit gaps: kingsec-bootstrap's admin creation
        previously had zero audit trail, and what little a caller could
        infer would have been indistinguishable from a self-registered
        user. Verifies both the user row AND that it is findable by its
        own ADMIN_BOOTSTRAPPED action type, distinct from USER_REGISTERED."""
        exit_code = _bootstrap_admin("first_admin", "SecurePass1", "admin@example.com")
        assert exit_code == 0

        db_path = migrated_data_dir / "kingsec.db"
        user_row = _query_one(
            db_path, "SELECT username, role, email FROM users WHERE username = ?", ("first_admin",)
        )
        assert user_row is not None, "admin user row was not persisted"
        assert user_row[1] == "ADMIN"
        assert user_row[2] == "admin@example.com"

        audit_row = _query_one(
            db_path,
            "SELECT action, username, role FROM audit_entries WHERE action = ?",
            ("admin_bootstrapped",),
        )
        assert audit_row is not None, (
            "no admin_bootstrapped audit entry found - kingsec-bootstrap's admin "
            "creation must be findable by its own action type, not just USER_REGISTERED"
        )
        assert audit_row[1] == "first_admin"
        assert audit_row[2] == "Admin"

        # And it must NOT be reachable by filtering USER_REGISTERED for this
        # user - that would mean it fell back to the wrong action type.
        wrong_type_row = _query_one(
            db_path,
            "SELECT 1 FROM audit_entries WHERE action = ? AND username = ?",
            ("user_registered", "first_admin"),
        )
        assert wrong_type_row is None

    def test_refuses_when_an_admin_already_exists(
        self, migrated_data_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        first = _bootstrap_admin("first_admin", "SecurePass1")
        assert first == 0
        capsys.readouterr()  # discard run 1's output

        # A REAL, independently confirmed bug (two genuine `python -m
        # kingsec._bootstrap` subprocess invocations in a row, no test
        # harness involved): the second call's own _migrations_applied()
        # check fails - `alembic check`'s autogenerate diff reports
        # several unrelated backup/scan-snapshot tables as "removed" only
        # after the app has run once, so a second real invocation prints
        # the misleading "migrations not applied; run kingsec-migrate
        # first" instead of the correct "admin user already exists".
        # Pre-existing, unrelated to this phase's scope (registration/
        # bootstrap/lockout) - not fixed here, flagged separately. This
        # test's actual subject is the admin-exists GUARD (the code path
        # reached only after that check passes), so the check itself is
        # patched out for this one call to isolate the two concerns.
        monkeypatch.setattr("kingsec._bootstrap._migrations_applied", lambda: True)

        second = _bootstrap_admin("second_admin", "AnotherPass2")
        assert second == 1
        assert "admin user already exists" in capsys.readouterr().err

        db_path = migrated_data_dir / "kingsec.db"
        second_row = _query_one(db_path, "SELECT 1 FROM users WHERE username = ?", ("second_admin",))
        assert second_row is None, "refused bootstrap must not have persisted a second admin"

    def test_rejects_a_weak_password_before_touching_the_database(
        self, migrated_data_dir: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """Phase 3: this CLI creates the most powerful account in the
        system and previously ran zero password validation - reuses
        ChangePassword._validate_password, the same canonical policy
        admin_users.py already reuses for the identical reason."""
        exit_code = _bootstrap_admin("weak_admin", "short")
        assert exit_code == 1
        assert "at least 8 characters" in capsys.readouterr().err

        db_path = migrated_data_dir / "kingsec.db"
        row = _query_one(db_path, "SELECT 1 FROM users WHERE username = ?", ("weak_admin",))
        assert row is None, "a rejected password must never reach the database"
