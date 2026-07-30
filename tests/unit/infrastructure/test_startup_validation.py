"""Tests for startup validation infrastructure."""



from kingsec.infrastructure.startup.startup_validator import (
    StartupCheck,
    StartupValidationReport,
    StartupValidator,
)


class TestStartupCheck:
    """Tests for StartupCheck dataclass."""

    def test_check_passed(self):
        """Test creating a passing check."""
        check = StartupCheck(
            name="test",
            passed=True,
            message="all good",
        )
        assert check.passed is True
        assert check.severity == "error"

    def test_check_failed(self):
        """Test creating a failing check."""
        check = StartupCheck(
            name="test",
            passed=False,
            message="something wrong",
            severity="warning",
        )
        assert check.passed is False
        assert check.severity == "warning"


class TestStartupValidationReport:
    """Tests for StartupValidationReport."""

    def test_all_passed(self):
        """Test report with all checks passing."""
        report = StartupValidationReport(
            checks=(
                StartupCheck(name="a", passed=True, message="ok"),
                StartupCheck(name="b", passed=True, message="ok"),
            ),
            passed=True,
        )
        assert report.passed is True
        assert len(report.errors) == 0
        assert len(report.warnings) == 0

    def test_has_errors(self):
        """Test report with failing error checks."""
        report = StartupValidationReport(
            checks=(
                StartupCheck(name="a", passed=True, message="ok"),
                StartupCheck(name="b", passed=False, message="fail", severity="error"),
            ),
            passed=False,
        )
        assert len(report.errors) == 1
        assert report.errors[0].name == "b"

    def test_has_warnings(self):
        """Test report with failing warning checks."""
        report = StartupValidationReport(
            checks=(
                StartupCheck(name="a", passed=False, message="warn", severity="warning"),
                StartupCheck(name="b", passed=True, message="ok"),
            ),
            passed=True,
        )
        assert len(report.warnings) == 1
        assert report.warnings[0].name == "a"


class TestStartupValidator:
    """Tests for StartupValidator."""

    def test_check_python_version_passes(self, tmp_path):
        """Test that Python 3.12+ check passes."""
        validator = StartupValidator(data_dir=tmp_path)
        check = validator.check_python_version()
        assert check.passed is True
        assert "Python" in check.message

    def test_check_data_directory_creates_and_writes(self, tmp_path):
        """Test that data directory check creates dir if missing."""
        data_dir = tmp_path / "new_data"
        validator = StartupValidator(data_dir=data_dir)
        check = validator.check_data_directory()
        assert check.passed is True
        assert data_dir.is_dir()

    def test_check_database_fresh_install(self, tmp_path):
        """Test database check on fresh install (no DB)."""
        validator = StartupValidator(data_dir=tmp_path)
        check = validator.check_database()
        assert check.passed is True
        assert "Fresh install" in check.message

    def test_check_database_with_existing_db(self, tmp_path):
        """Test database check with existing database file."""
        db_path = tmp_path / "kingsec.db"
        db_path.write_bytes(b"fake sqlite db content")
        validator = StartupValidator(data_dir=tmp_path)
        check = validator.check_database()
        assert check.passed is False
        assert "not accessible" in check.message.lower()

    def test_check_disk_space_passes(self, tmp_path):
        """Test disk space check passes when sufficient space."""
        validator = StartupValidator(data_dir=tmp_path)
        check = validator.check_disk_space(min_free_mb=1)
        assert check.passed is True

    def test_check_disk_space_fails_when_insufficient(self, tmp_path):
        """Test disk space check fails with very high requirement."""
        validator = StartupValidator(data_dir=tmp_path)
        check = validator.check_disk_space(min_free_mb=999999999)
        assert check.passed is False
        assert "disk space" in check.message.lower()

    def test_check_migrations_no_dir(self, tmp_path):
        """Test migrations check when no alembic dir."""
        validator = StartupValidator(data_dir=tmp_path)
        check = validator.check_migrations()
        assert check.passed is True
        assert "Fresh install" in check.message or "No migrations" in check.message

    def test_validate_all_returns_report(self, tmp_path):
        """Test that validate_all returns a complete report."""
        validator = StartupValidator(data_dir=tmp_path)
        report = validator.validate_all()
        assert isinstance(report, StartupValidationReport)
        assert len(report.checks) >= 5
        # Should pass on a clean test directory
        assert report.passed is True
