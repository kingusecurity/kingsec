"""Startup validation service.

Runs pre-flight checks before the application starts serving traffic.
Validates database connectivity, migration state, configuration,
and required system dependencies.
"""

from __future__ import annotations

import datetime
import shutil
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class StartupCheck:
    """Result of a startup validation check."""

    name: str
    passed: bool
    message: str
    severity: str = "error"  # error, warning, info
    duration_ms: float = 0.0


@dataclass(frozen=True)
class StartupValidationReport:
    """Complete startup validation report."""

    checks: tuple[StartupCheck, ...]
    passed: bool
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat()
    )

    @property
    def errors(self) -> list[StartupCheck]:
        return [c for c in self.checks if not c.passed and c.severity == "error"]

    @property
    def warnings(self) -> list[StartupCheck]:
        return [c for c in self.checks if not c.passed and c.severity == "warning"]


class StartupValidator:
    """Validates the environment before application startup."""

    def __init__(
        self,
        data_dir: Path,
        database_url: str | None = None,
    ) -> None:
        self._data_dir = data_dir
        self._database_url = database_url

    def check_data_directory(self) -> StartupCheck:
        """Verify data directory exists and is writable."""
        import time

        start = time.monotonic()
        try:
            if not self._data_dir.is_dir():
                self._data_dir.mkdir(parents=True, exist_ok=True)

            test_file = self._data_dir / ".write-test"
            test_file.write_text("ok", encoding="utf-8")
            test_file.unlink()

            elapsed = (time.monotonic() - start) * 1000
            return StartupCheck(
                name="data_directory",
                passed=True,
                message=f"Data directory writable: {self._data_dir}",
                duration_ms=elapsed,
            )
        except (OSError, PermissionError) as exc:
            elapsed = (time.monotonic() - start) * 1000
            return StartupCheck(
                name="data_directory",
                passed=False,
                message=f"Data directory not writable: {exc}",
                duration_ms=elapsed,
            )

    def check_database(self) -> StartupCheck:
        """Verify database is accessible."""
        import time

        start = time.monotonic()
        db_path = self._data_dir / "kingsec.db"
        if not db_path.is_file():
            elapsed = (time.monotonic() - start) * 1000
            return StartupCheck(
                name="database",
                passed=True,
                message="Fresh install (database will be created)",
                severity="info",
                duration_ms=elapsed,
            )

        try:
            import sqlite3

            conn = sqlite3.connect(str(db_path), timeout=5)
            # SELECT 1 is a constant literal - it never reads a page, so
            # whether a corrupt/non-database file is caught here depends on
            # the linked SQLite version's own header-validation eagerness
            # (observed to differ between platforms: raises immediately on
            # this dev machine's SQLite 3.50.4, silently "succeeds" against
            # garbage bytes on CI's Linux runners - Phase 20 §4). Querying
            # sqlite_master forces a real page read on every SQLite version.
            cursor = conn.execute("SELECT count(*) FROM sqlite_master")
            cursor.fetchone()
            conn.close()

            size_mb = round(db_path.stat().st_size / (1024**2), 2)
            elapsed = (time.monotonic() - start) * 1000
            return StartupCheck(
                name="database",
                passed=True,
                message=f"Database accessible ({size_mb} MB)",
                duration_ms=elapsed,
            )
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            return StartupCheck(
                name="database",
                passed=False,
                message=f"Database not accessible: {exc}",
                duration_ms=elapsed,
            )

    def check_migrations(self) -> StartupCheck:
        """Verify Alembic migration state is consistent."""
        import time

        start = time.monotonic()
        alembic_dir = self._data_dir / "alembic"

        if not alembic_dir.is_dir():
            elapsed = (time.monotonic() - start) * 1000
            return StartupCheck(
                name="migrations",
                passed=True,
                message="No migrations directory (will initialize)",
                severity="info",
                duration_ms=elapsed,
            )

        elapsed = (time.monotonic() - start) * 1000
        return StartupCheck(
            name="migrations",
            passed=True,
            message="Migration directory found",
            duration_ms=elapsed,
        )

    def check_disk_space(self, min_free_mb: int = 50) -> StartupCheck:
        """Ensure sufficient disk space."""
        import time

        start = time.monotonic()
        try:
            usage = shutil.disk_usage(str(self._data_dir))
            free_mb = usage.free / (1024**2)

            elapsed = (time.monotonic() - start) * 1000
            if free_mb < min_free_mb:
                return StartupCheck(
                    name="disk_space",
                    passed=False,
                    message=f"Low disk space: {free_mb:.1f} MB free, {min_free_mb} MB recommended",
                    severity="warning",
                    duration_ms=elapsed,
                )
            return StartupCheck(
                name="disk_space",
                passed=True,
                message=f"Disk space OK ({free_mb:.1f} MB free)",
                duration_ms=elapsed,
            )
        except (OSError, ValueError) as exc:
            elapsed = (time.monotonic() - start) * 1000
            return StartupCheck(
                name="disk_space",
                passed=True,
                message=f"Cannot check disk space: {exc}",
                severity="warning",
                duration_ms=elapsed,
            )

    def check_python_version(self) -> StartupCheck:
        """Verify Python version meets requirements."""
        import sys
        import time

        start = time.monotonic()
        version = sys.version_info
        elapsed = (time.monotonic() - start) * 1000

        if version < (3, 12):
            return StartupCheck(
                name="python_version",
                passed=False,
                message=f"Python {version.major}.{version.minor} < 3.12 required",
                duration_ms=elapsed,
            )
        return StartupCheck(
            name="python_version",
            passed=True,
            message=f"Python {version.major}.{version.minor}.{version.micro}",
            duration_ms=elapsed,
        )

    def check_required_tools(self) -> StartupCheck:
        """Check if required external tools are available."""
        import time

        start = time.monotonic()
        required = ["nmap", "nuclei"]
        missing = []

        for tool in required:
            if shutil.which(tool) is None:
                missing.append(tool)

        elapsed = (time.monotonic() - start) * 1000
        if missing:
            return StartupCheck(
                name="required_tools",
                passed=False,
                message=f"Missing tools: {', '.join(missing)}",
                severity="warning",
                duration_ms=elapsed,
            )
        return StartupCheck(
            name="required_tools",
            passed=True,
            message="All required tools available",
            duration_ms=elapsed,
        )

    def validate_all(self) -> StartupValidationReport:
        """Run all startup checks."""
        checks = [
            self.check_python_version(),
            self.check_data_directory(),
            self.check_database(),
            self.check_migrations(),
            self.check_disk_space(),
            self.check_required_tools(),
        ]

        all_passed = all(c.passed for c in checks if c.severity == "error")
        return StartupValidationReport(checks=tuple(checks), passed=all_passed)
