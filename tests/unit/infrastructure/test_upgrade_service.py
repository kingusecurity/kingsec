"""Tests for upgrade service infrastructure."""


import pytest

from kingsec.infrastructure.upgrade.upgrade_service import (
    UpgradePlan,
    UpgradeService,
    VersionInfo,
)


class TestVersionInfo:
    """Tests for VersionInfo dataclass."""

    def test_parse_valid_version(self):
        """Test parsing a valid version string."""
        v = VersionInfo.parse("2.0.0")
        assert v.major == 2
        assert v.minor == 0
        assert v.patch == 0

    def test_parse_with_v_prefix(self):
        """Test parsing version with v prefix."""
        v = VersionInfo.parse("v1.2.3")
        assert v.major == 1
        assert v.minor == 2
        assert v.patch == 3

    def test_parse_invalid_format(self):
        """Test parsing invalid version format."""
        with pytest.raises(ValueError, match="Invalid version format"):
            VersionInfo.parse("1.2")

    def test_str_representation(self):
        """Test string representation."""
        v = VersionInfo(major=1, minor=2, patch=3)
        assert str(v) == "1.2.3"

    def test_is_upgrade(self):
        """Test is_upgrade comparison."""
        v1 = VersionInfo.parse("1.0.0")
        v2 = VersionInfo.parse("2.0.0")
        assert v2.is_upgrade(v1) is True
        assert v1.is_upgrade(v2) is False

    def test_is_compatible_with(self):
        """Test compatible version check (same major)."""
        v1 = VersionInfo.parse("2.0.0")
        v2 = VersionInfo.parse("2.1.0")
        assert v1.is_compatible_with(v2) is True

    def test_not_compatible_with_different_major(self):
        """Test incompatible versions (different major)."""
        v1 = VersionInfo.parse("1.0.0")
        v2 = VersionInfo.parse("2.0.0")
        assert v1.is_compatible_with(v2) is False


class TestUpgradeService:
    """Tests for UpgradeService."""

    def test_get_installed_version_none(self, tmp_path):
        """Test getting version when none set."""
        service = UpgradeService(data_dir=tmp_path, current_version="1.0.0")
        assert service.get_installed_version() is None

    def test_set_and_get_installed_version(self, tmp_path):
        """Test setting and getting installed version."""
        service = UpgradeService(data_dir=tmp_path, current_version="1.0.0")
        service.set_installed_version("2.0.0")
        assert service.get_installed_version() == "2.0.0"

    def test_check_database_compatibility_fresh(self, tmp_path):
        """Test database check on fresh install."""
        service = UpgradeService(data_dir=tmp_path, current_version="1.0.0")
        check = service.check_database_compatibility()
        assert check.passed is True
        assert "Fresh install" in check.message

    def test_check_database_compatibility_existing(self, tmp_path):
        """Test database check with existing database."""
        db_path = tmp_path / "kingsec.db"
        db_path.write_bytes(b"fake db content " * 1000)
        service = UpgradeService(data_dir=tmp_path, current_version="1.0.0")
        check = service.check_database_compatibility()
        assert check.passed is True
        assert "MB" in check.message

    def test_check_disk_space_passes(self, tmp_path):
        """Test disk space check passes normally."""
        service = UpgradeService(data_dir=tmp_path, current_version="1.0.0")
        check = service.check_disk_space(min_free_mb=1)
        assert check.passed is True

    def test_check_disk_space_fails_when_insufficient(self, tmp_path):
        """Test disk space check fails with huge requirement."""
        service = UpgradeService(data_dir=tmp_path, current_version="1.0.0")
        check = service.check_disk_space(min_free_mb=999999999)
        assert check.passed is False

    def test_check_running_processes_no_pid(self, tmp_path):
        """Test process check with no PID file."""
        service = UpgradeService(data_dir=tmp_path, current_version="1.0.0")
        check = service.check_running_processes()
        assert check.passed is True

    def test_check_config_compatibility(self, tmp_path):
        """Test config compatibility check."""
        service = UpgradeService(data_dir=tmp_path, current_version="1.0.0")
        check = service.check_config_compatibility()
        assert check.passed is True

    def test_create_backup(self, tmp_path):
        """Test creating a backup."""
        db_path = tmp_path / "kingsec.db"
        db_path.write_bytes(b"test db content")
        service = UpgradeService(data_dir=tmp_path, current_version="1.0.0")
        backup_path = service.create_backup()
        assert backup_path is not None
        assert backup_path.exists()
        assert backup_path.name.startswith("kingsec-pre-upgrade-")

    def test_create_backup_no_db(self, tmp_path):
        """Test creating backup when no database exists."""
        service = UpgradeService(data_dir=tmp_path, current_version="1.0.0")
        backup_path = service.create_backup()
        assert backup_path is None

    def test_create_plan(self, tmp_path):
        """Test creating an upgrade plan."""
        service = UpgradeService(data_dir=tmp_path, current_version="1.0.0")
        plan = service.create_plan("2.0.0")
        assert isinstance(plan, UpgradePlan)
        assert plan.from_version == "1.0.0"
        assert plan.to_version == "2.0.0"
        assert plan.backup_required is True
        assert len(plan.checks) >= 4
        assert len(plan.migration_steps) >= 3

    def test_save_and_load_version_manifest(self, tmp_path):
        """Test saving and loading version manifest."""
        service = UpgradeService(data_dir=tmp_path, current_version="1.0.0")
        manifest = {"version": "1.0.0", "installed_at": "2026-01-01"}
        service.save_version_manifest(manifest)
        loaded = service.load_version_manifest()
        assert loaded["version"] == "1.0.0"

    def test_load_version_manifest_empty(self, tmp_path):
        """Test loading manifest when none exists."""
        service = UpgradeService(data_dir=tmp_path, current_version="1.0.0")
        loaded = service.load_version_manifest()
        assert loaded == {}
