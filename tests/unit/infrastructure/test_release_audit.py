"""Tests for release audit infrastructure."""



from kingsec.infrastructure.audit.release_audit import (
    ReleaseAuditReport,
    ReleaseAuditService,
    ReleaseEntry,
)


class TestReleaseEntry:
    """Tests for ReleaseEntry dataclass."""

    def test_release_entry_creation(self):
        """Test creating a release entry."""
        entry = ReleaseEntry(
            version="2.0.0",
            released_at="2026-01-01T00:00:00",
            release_type="major",
            changes=("New feature",),
            breaking_changes=(),
        )
        assert entry.version == "2.0.0"
        assert entry.release_type == "major"
        assert "New feature" in entry.changes


class TestReleaseAuditService:
    """Tests for ReleaseAuditService."""

    def test_record_release(self, tmp_path):
        """Test recording a release."""
        service = ReleaseAuditService(data_dir=tmp_path)
        entry = service.record_release(
            version="2.0.0",
            release_type="major",
            changes=("Feature A", "Feature B"),
        )
        assert entry.version == "2.0.0"
        assert entry.release_type == "major"

    def test_record_multiple_releases(self, tmp_path):
        """Test recording multiple releases."""
        service = ReleaseAuditService(data_dir=tmp_path)
        service.record_release(version="1.0.0", release_type="major")
        service.record_release(version="1.1.0", release_type="minor")
        service.record_release(version="1.1.1", release_type="patch")

        report = service.generate_report()
        assert report.total_releases == 3
        assert len(report.releases) == 3

    def test_record_upgrade(self, tmp_path):
        """Test recording an upgrade."""
        service = ReleaseAuditService(data_dir=tmp_path)
        entry = service.record_upgrade(
            from_version="1.0.0",
            to_version="2.0.0",
            upgraded_by="admin",
        )
        assert entry.upgrade_from == "1.0.0"
        assert entry.version == "2.0.0"
        assert entry.upgraded_by == "admin"

    def test_get_and_set_current_version(self, tmp_path):
        """Test setting and getting current version."""
        service = ReleaseAuditService(data_dir=tmp_path)
        assert service.get_current_version() is None

        service.set_current_version("2.0.0-rc1")
        assert service.get_current_version() == "2.0.0-rc1"

    def test_generate_report_empty(self, tmp_path):
        """Test generating report with no releases."""
        service = ReleaseAuditService(data_dir=tmp_path)
        report = service.generate_report()
        assert isinstance(report, ReleaseAuditReport)
        assert report.total_releases == 0
        assert report.current_version == "unknown"

    def test_generate_report_with_data(self, tmp_path):
        """Test generating report with release data."""
        service = ReleaseAuditService(data_dir=tmp_path)
        service.set_current_version("1.1.0")
        service.record_release(version="1.0.0", release_type="major")
        service.record_upgrade(from_version="1.0.0", to_version="1.1.0")

        report = service.generate_report()
        assert report.current_version == "1.1.0"
        assert report.total_releases == 2
        assert len(report.upgrade_history) == 1

    def test_get_version_changelog(self, tmp_path):
        """Test getting changelog for a specific version."""
        service = ReleaseAuditService(data_dir=tmp_path)
        service.record_release(
            version="2.0.0",
            release_type="major",
            changes=("New feature",),
            notes="Major release",
        )

        entry = service.get_version_changelog("2.0.0")
        assert entry is not None
        assert entry.version == "2.0.0"
        assert "New feature" in entry.changes

    def test_get_version_changelog_not_found(self, tmp_path):
        """Test getting changelog for non-existent version."""
        service = ReleaseAuditService(data_dir=tmp_path)
        entry = service.get_version_changelog("9.9.9")
        assert entry is None

    def test_record_release_with_breaking_changes(self, tmp_path):
        """Test recording release with breaking changes."""
        service = ReleaseAuditService(data_dir=tmp_path)
        entry = service.record_release(
            version="2.0.0",
            release_type="major",
            changes=("Feature A",),
            breaking_changes=("Removed old API",),
        )
        assert "Removed old API" in entry.breaking_changes
