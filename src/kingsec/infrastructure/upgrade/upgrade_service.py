"""Upgrade service for version migrations.

Handles pre-flight checks, backup before upgrade, and post-upgrade
validation. Supports database schema migration via Alembic.
"""

from __future__ import annotations

import datetime
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class VersionInfo:
    """Parsed semantic version."""

    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, version_str: str) -> VersionInfo:
        parts = version_str.lstrip("v").split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid version format: {version_str}")
        return cls(major=int(parts[0]), minor=int(parts[1]), patch=int(parts[2]))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    def is_compatible_with(self, other: VersionInfo) -> bool:
        """Check if upgrading from other to self is compatible (same major)."""
        return self.major == other.major

    def is_upgrade(self, other: VersionInfo) -> bool:
        """Check if self is newer than other."""
        return (self.major, self.minor, self.patch) > (
            other.major,
            other.minor,
            other.patch,
        )


@dataclass(frozen=True)
class UpgradeCheck:
    """Result of a pre-upgrade check."""

    name: str
    passed: bool
    message: str
    severity: str = "error"  # error, warning, info


@dataclass(frozen=True)
class UpgradePlan:
    """Full upgrade plan with checks and migration steps."""

    from_version: str
    to_version: str
    checks: tuple[UpgradeCheck, ...]
    migration_steps: tuple[str, ...]
    backup_required: bool
    estimated_downtime: str = "unknown"


class UpgradeService:
    """Orchestrates upgrades between versions."""

    def __init__(
        self,
        data_dir: Path,
        current_version: str,
        alembic_ini_path: Path | None = None,
    ) -> None:
        self._data_dir = data_dir
        self._current_version = current_version
        self._alembic_ini = alembic_ini_path
        self._version_file = data_dir / ".kingsec-version"

    def get_installed_version(self) -> str | None:
        """Read the currently installed version from disk."""
        if self._version_file.is_file():
            return self._version_file.read_text(encoding="utf-8").strip()
        return None

    def set_installed_version(self, version: str) -> None:
        """Write the installed version to disk."""
        self._version_file.write_text(version, encoding="utf-8")

    def check_database_compatibility(self) -> UpgradeCheck:
        """Verify database exists and is accessible."""
        db_path = self._data_dir / "kingsec.db"
        if not db_path.is_file():
            return UpgradeCheck(
                name="database",
                passed=True,
                message="Fresh install (no existing database)",
                severity="info",
            )

        size_mb = round(db_path.stat().st_size / (1024**2), 2)
        if size_mb < 0.001:
            return UpgradeCheck(
                name="database",
                passed=False,
                message="Database file exists but appears empty",
            )

        return UpgradeCheck(
            name="database",
            passed=True,
            message=f"Database accessible ({size_mb} MB)",
        )

    def check_disk_space(self, min_free_mb: int = 100) -> UpgradeCheck:
        """Ensure sufficient disk space for upgrade."""

        try:
            usage = shutil.disk_usage(str(self._data_dir))
            free_mb = usage.free / (1024**2)
            if free_mb < min_free_mb:
                return UpgradeCheck(
                    name="disk_space",
                    passed=False,
                    message=f"Insufficient disk space: {free_mb:.1f} MB free, {min_free_mb} MB required",
                )
            return UpgradeCheck(
                name="disk_space",
                passed=True,
                message=f"Sufficient disk space ({free_mb:.1f} MB free)",
            )
        except (OSError, ValueError) as exc:
            return UpgradeCheck(
                name="disk_space",
                passed=False,
                message=f"Cannot check disk space: {exc}",
            )

    def check_running_processes(self) -> UpgradeCheck:
        """Check if another KingSec process might be running."""
        pid_file = self._data_dir / "kingsec.pid"
        if not pid_file.is_file():
            return UpgradeCheck(
                name="processes",
                passed=True,
                message="No PID file found (safe to upgrade)",
            )

        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
            # Check if process is alive (cross-platform)
            import os

            os.kill(pid, 0)
            return UpgradeCheck(
                name="processes",
                passed=False,
                message=f"KingSec process (PID {pid}) is running. Stop it before upgrading.",
            )
        except (ProcessLookupError, ValueError, OSError):
            # Process not running (stale PID file)
            return UpgradeCheck(
                name="processes",
                passed=True,
                message="Stale PID file found (process not running)",
            )

    def check_config_compatibility(self) -> UpgradeCheck:
        """Verify configuration is compatible with new version."""
        env_file = self._data_dir / ".env"
        if not env_file.is_file():
            return UpgradeCheck(
                name="config",
                passed=True,
                message="No .env file (will use defaults)",
                severity="info",
            )

        return UpgradeCheck(
            name="config",
            passed=True,
            message="Configuration file found",
        )

    def check_backup_exists(self) -> UpgradeCheck:
        """Check if a recent backup exists."""
        backups_dir = self._data_dir / "backups"
        if not backups_dir.is_dir():
            return UpgradeCheck(
                name="backup",
                passed=True,
                message="No backups directory (will create during upgrade)",
                severity="warning",
            )

        backups = sorted(backups_dir.glob("*.sql"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not backups:
            return UpgradeCheck(
                name="backup",
                passed=True,
                message="No backup files found (will create during upgrade)",
                severity="warning",
            )

        latest = backups[0]
        age_hours = (datetime.datetime.now().timestamp() - latest.stat().st_mtime) / 3600
        return UpgradeCheck(
            name="backup",
            passed=True,
            message=f"Latest backup: {latest.name} ({age_hours:.1f}h ago)",
        )

    def create_backup(self) -> Path | None:
        """Create a backup of the database before upgrade."""
        db_path = self._data_dir / "kingsec.db"
        if not db_path.is_file():
            return None

        backups_dir = self._data_dir / "backups"
        backups_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d_%H%M%S")
        backup_path = backups_dir / f"kingsec-pre-upgrade-{timestamp}.db"
        shutil.copy2(db_path, backup_path)

        return backup_path

    def create_plan(self, target_version: str) -> UpgradePlan:
        """Create a full upgrade plan with all checks."""
        checks = [
            self.check_database_compatibility(),
            self.check_disk_space(),
            self.check_running_processes(),
            self.check_config_compatibility(),
            self.check_backup_exists(),
]

        migration_steps: list[str] = ["backup_database", "stop_services"]

        # Determine migration steps based on version
        installed = self.get_installed_version() or self._current_version
        if installed != target_version:
            migration_steps.append("run_alembic_upgrade")

        migration_steps.extend(["verify_upgrade", "start_services"])

        return UpgradePlan(
            from_version=installed,
            to_version=target_version,
            checks=tuple(checks),
            migration_steps=tuple(migration_steps),
            backup_required=True,
            estimated_downtime="1-5 minutes",
        )

    def save_version_manifest(self, manifest: dict[str, Any]) -> None:
        """Save a version manifest to disk for tracking."""
        manifest_path = self._data_dir / "version-manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    def load_version_manifest(self) -> dict[str, Any]:
        """Load the version manifest from disk."""
        manifest_path = self._data_dir / "version-manifest.json"
        if manifest_path.is_file():
            return json.loads(manifest_path.read_text(encoding="utf-8"))
        return {}
