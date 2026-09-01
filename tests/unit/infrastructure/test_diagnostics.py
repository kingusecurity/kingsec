"""Tests for diagnostics infrastructure."""

import json
import shutil
import tempfile
from pathlib import Path

from kingsec.infrastructure.monitoring.diagnostics import (
    DiagnosticsCollector,
    SystemInfo,
    create_diagnostics_bundle,
)


class TestSystemInfo:
    """Tests for SystemInfo dataclass."""

    def test_system_info_populated(self):
        """Test that SystemInfo fields are populated."""
        info = SystemInfo()
        assert info.os_name  # Should have a value
        assert info.python_version
        assert info.pid > 0


class TestDiagnosticsCollector:
    """Tests for DiagnosticsCollector."""

    def test_collect_system_info(self, tmp_path):
        """Test collecting system info."""
        collector = DiagnosticsCollector(data_dir=tmp_path)
        info = collector.collect_system_info()
        assert "os" in info
        assert "python" in info
        assert "machine" in info
        assert "pid" in info

    def test_collect_config_summary(self, tmp_path):
        """Test collecting config summary."""
        collector = DiagnosticsCollector(data_dir=tmp_path)
        config = collector.collect_config_summary()
        assert "kingsec_env" in config
        assert "kingsec_data_dir" in config

    def test_collect_health_status_unreachable(self, tmp_path):
        """Test health status when server not running."""
        collector = DiagnosticsCollector(data_dir=tmp_path)
        health = collector.collect_health_status()
        assert health["status"] == "unreachable"

    def test_collect_disk_usage(self, tmp_path):
        """Test collecting disk usage."""
        collector = DiagnosticsCollector(data_dir=tmp_path)
        disk = collector.collect_disk_usage()
        assert "total_gb" in disk
        assert "free_gb" in disk
        assert disk["free_gb"] >= 0

    def test_collect_recent_logs_no_dir(self, tmp_path):
        """Test collecting logs when no log directory."""
        collector = DiagnosticsCollector(data_dir=tmp_path)
        logs = collector.collect_recent_logs()
        assert len(logs) >= 1
        assert "No log directory" in logs[0]

    def test_collect_recent_logs_with_logs(self, tmp_path):
        """Test collecting logs from log directory."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "kingsec.log"
        log_file.write_text("line1\nline2\nline3\n", encoding="utf-8")

        collector = DiagnosticsCollector(data_dir=tmp_path)
        logs = collector.collect_recent_logs(lines=2)
        assert len(logs) == 2

    def test_collect_database_info_no_db(self, tmp_path):
        """Test database info when no database."""
        collector = DiagnosticsCollector(data_dir=tmp_path)
        db_info = collector.collect_database_info()
        assert db_info["exists"] is False

    def test_collect_database_info_with_db(self, tmp_path):
        """Test database info with existing database."""
        db_path = tmp_path / "kingsec.db"
        db_path.write_bytes(b"fake db " * 1000)
        collector = DiagnosticsCollector(data_dir=tmp_path)
        db_info = collector.collect_database_info()
        assert db_info["exists"] is True
        assert "size_mb" in db_info

    def test_collect_environment_variables(self, tmp_path):
        """Test collecting non-sensitive environment variables."""
        collector = DiagnosticsCollector(data_dir=tmp_path)
        env = collector.collect_environment_variables()
        # Should not contain secrets
        for key in env:
            assert "SECRET" not in key.upper()
            assert "PASSWORD" not in key.upper()
            assert "TOKEN" not in key.upper()

    def test_collect_all(self, tmp_path):
        """Test collecting all diagnostics."""
        collector = DiagnosticsCollector(data_dir=tmp_path, app_version="2.0.0-rc1")
        data = collector.collect_all()
        assert data["version"] == "2.0.0-rc1"
        assert "collected_at" in data
        assert "system" in data
        assert "config" in data
        assert "health" in data
        assert "disk" in data
        assert "database" in data
        assert "environment" in data
        assert "recent_logs" in data


class TestDiagnosticsBundle:
    """Tests for diagnostics bundle creation."""

    def test_create_bundle(self, tmp_path):
        """Test creating a diagnostics bundle."""
        bundle_path = create_diagnostics_bundle(
            data_dir=tmp_path,
            app_version="2.0.0-rc1",
            output_dir=tmp_path,
        )
        assert bundle_path.exists()
        assert bundle_path.suffix == ".zip"

    def test_bundle_contains_json(self, tmp_path):
        """Test that bundle contains JSON file."""
        bundle_path = create_diagnostics_bundle(
            data_dir=tmp_path,
            app_version="2.0.0-rc1",
            output_dir=tmp_path,
        )
        import zipfile

        with zipfile.ZipFile(bundle_path, "r") as zf:
            names = zf.namelist()
            json_files = [n for n in names if n.endswith(".json")]
            assert len(json_files) >= 1

    def test_bundle_json_content(self, tmp_path):
        """Test that bundle JSON has expected content."""
        bundle_path = create_diagnostics_bundle(
            data_dir=tmp_path,
            app_version="2.0.0-rc1",
            output_dir=tmp_path,
        )
        import zipfile

        with zipfile.ZipFile(bundle_path, "r") as zf:
            json_files = [n for n in zf.namelist() if n.endswith(".json")]
            content = zf.read(json_files[0])
            data = json.loads(content)
            assert data["version"] == "2.0.0-rc1"
            assert "system" in data


class TestDiagnosticsBundleDefaultOutputDirIsNotPredictable:
    """KSEC-86-03 (diagnostics temp-file TOCTOU, Phase-84 carry-forward):
    the default output_dir=None path used to write a fixed, guessable
    filename directly into the shared system temp directory via a plain
    non-exclusive open() - any other local user on that shared directory
    could read the bundle or pre-plant a symlink at the predictable path.
    These exercise the REAL default path (no output_dir override)."""

    def test_default_output_dir_is_not_the_shared_system_temp_root(self) -> None:
        bundle_path = create_diagnostics_bundle(app_version="1.0.0")
        try:
            system_temp_root = Path(tempfile.gettempdir()).resolve()
            assert bundle_path.parent.resolve() != system_temp_root, (
                "the bundle must not be written directly into the shared system temp root"
            )
            assert bundle_path.parent.resolve().parent == system_temp_root, (
                "the unique container directory should still live under the system temp root, just not be it"
            )
        finally:
            shutil.rmtree(bundle_path.parent, ignore_errors=True)

    def test_two_default_bundles_land_in_different_unpredictable_directories(self) -> None:
        first = create_diagnostics_bundle(app_version="1.0.0")
        second = create_diagnostics_bundle(app_version="1.0.0")
        try:
            assert first.parent != second.parent, (
                "the container directory must be unique per call, not a fixed/guessable path an attacker could "
                "pre-plant a symlink at"
            )
        finally:
            shutil.rmtree(first.parent, ignore_errors=True)
            shutil.rmtree(second.parent, ignore_errors=True)
