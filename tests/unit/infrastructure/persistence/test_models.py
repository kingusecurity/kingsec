from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from kingsec.infrastructure.persistence import (
    AssetModel,
    FindingModel,
    JobModel,
    ReportModel,
    ScanModel,
    create_database_engine,
    create_schema,
)

# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def engine():
    eng = create_database_engine(url="sqlite://")
    create_schema(eng)
    try:
        yield eng
    finally:
        eng.dispose()


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s


# ===========================================================================
# Table names
# ===========================================================================


class TestTableNames:
    def test_scan_model_table_name(self) -> None:
        assert ScanModel.__tablename__ == "scan_results"

    def test_finding_model_table_name(self) -> None:
        assert FindingModel.__tablename__ == "scan_findings"

    def test_report_model_table_name(self) -> None:
        assert ReportModel.__tablename__ == "scan_reports"

    def test_job_model_table_name(self) -> None:
        assert JobModel.__tablename__ == "scan_jobs"

    def test_asset_model_table_name(self) -> None:
        assert AssetModel.__tablename__ == "assets"


# ===========================================================================
# Columns — ScanModel
# ===========================================================================


class TestScanModelColumns:
    def test_has_id_column(self) -> None:
        assert "id" in ScanModel.__table__.columns

    def test_has_target_column(self) -> None:
        col = ScanModel.__table__.columns["target"]
        assert not col.nullable

    def test_has_status_column(self) -> None:
        col = ScanModel.__table__.columns["status"]
        assert not col.nullable

    def test_has_created_at_column(self) -> None:
        col = ScanModel.__table__.columns["created_at"]
        assert not col.nullable

    def test_has_completed_at_column(self) -> None:
        col = ScanModel.__table__.columns["completed_at"]
        assert col.nullable

    def test_has_scanner_count_column(self) -> None:
        col = ScanModel.__table__.columns["scanner_count"]
        assert not col.nullable
        assert col.type.python_type is int


class TestScanModelIndexes:
    def test_target_is_indexed(self) -> None:
        idx_names = {i.name for i in ScanModel.__table__.indexes}
        matching = [n for n in idx_names if "target" in n]
        assert len(matching) >= 1

    def test_status_is_indexed(self) -> None:
        idx_names = {i.name for i in ScanModel.__table__.indexes}
        matching = [n for n in idx_names if "status" in n]
        assert len(matching) >= 1


# ===========================================================================
# Columns — FindingModel
# ===========================================================================


class TestFindingModelColumns:
    def test_has_id_column(self) -> None:
        assert "id" in FindingModel.__table__.columns

    def test_has_scan_id_fk(self) -> None:
        col = FindingModel.__table__.columns["scan_id"]
        assert not col.nullable
        fks = list(col.foreign_keys)
        assert len(fks) == 1
        assert fks[0].column.table.name == "scan_results"

    def test_has_title_column(self) -> None:
        col = FindingModel.__table__.columns["title"]
        assert not col.nullable

    def test_has_description_column(self) -> None:
        col = FindingModel.__table__.columns["description"]
        assert not col.nullable

    def test_has_severity_column(self) -> None:
        col = FindingModel.__table__.columns["severity"]
        assert not col.nullable

    def test_has_scanner_column(self) -> None:
        col = FindingModel.__table__.columns["scanner"]
        assert col.nullable

    def test_has_asset_column(self) -> None:
        col = FindingModel.__table__.columns["asset"]
        assert col.nullable

    def test_has_asset_id_fk(self) -> None:
        col = FindingModel.__table__.columns["asset_id"]
        assert col.nullable
        fks = list(col.foreign_keys)
        assert len(fks) == 1
        assert fks[0].column.table.name == "assets"

    def test_has_created_at_column(self) -> None:
        col = FindingModel.__table__.columns["created_at"]
        assert not col.nullable


class TestFindingModelIndexes:
    def test_scan_id_is_indexed(self) -> None:
        idx_names = {i.name for i in FindingModel.__table__.indexes}
        matching = [n for n in idx_names if "scan_id" in n]
        assert len(matching) >= 1

    def test_severity_is_indexed(self) -> None:
        idx_names = {i.name for i in FindingModel.__table__.indexes}
        matching = [n for n in idx_names if "severity" in n]
        assert len(matching) >= 1

    def test_asset_id_is_indexed(self) -> None:
        idx_names = {i.name for i in FindingModel.__table__.indexes}
        matching = [n for n in idx_names if "asset_id" in n]
        assert len(matching) >= 1


# ===========================================================================
# Columns — ReportModel
# ===========================================================================


class TestReportModelColumns:
    def test_has_id_column(self) -> None:
        assert "id" in ReportModel.__table__.columns

    def test_has_scan_id_fk(self) -> None:
        col = ReportModel.__table__.columns["scan_id"]
        assert not col.nullable
        fks = list(col.foreign_keys)
        assert len(fks) == 1
        assert fks[0].column.table.name == "scan_results"

    def test_has_format_column(self) -> None:
        col = ReportModel.__table__.columns["format"]
        assert not col.nullable

    def test_has_created_at_column(self) -> None:
        col = ReportModel.__table__.columns["created_at"]
        assert not col.nullable

    def test_has_content_column(self) -> None:
        col = ReportModel.__table__.columns["content"]
        assert not col.nullable


# ===========================================================================
# Columns — JobModel
# ===========================================================================


class TestJobModelColumns:
    def test_has_id_column(self) -> None:
        assert "id" in JobModel.__table__.columns

    def test_has_status_column(self) -> None:
        col = JobModel.__table__.columns["status"]
        assert not col.nullable

    def test_has_target_column(self) -> None:
        col = JobModel.__table__.columns["target"]
        assert not col.nullable

    def test_has_created_at_column(self) -> None:
        col = JobModel.__table__.columns["created_at"]
        assert not col.nullable

    def test_has_updated_at_column(self) -> None:
        col = JobModel.__table__.columns["updated_at"]
        assert not col.nullable

    def test_no_foreign_keys(self) -> None:
        for col in JobModel.__table__.columns:
            assert len(list(col.foreign_keys)) == 0


# ===========================================================================
# Columns — AssetModel
# ===========================================================================


class TestAssetModelColumns:
    def test_has_id_column(self) -> None:
        assert "id" in AssetModel.__table__.columns

    def test_has_hostname_column(self) -> None:
        col = AssetModel.__table__.columns["hostname"]
        assert col.nullable

    def test_has_ip_address_column(self) -> None:
        col = AssetModel.__table__.columns["ip_address"]
        assert col.nullable

    def test_has_operating_system_column(self) -> None:
        col = AssetModel.__table__.columns["operating_system"]
        assert col.nullable

    def test_has_owner_column(self) -> None:
        col = AssetModel.__table__.columns["owner"]
        assert col.nullable

    def test_has_criticality_column(self) -> None:
        col = AssetModel.__table__.columns["criticality"]
        assert col.nullable

    def test_has_created_at_column(self) -> None:
        col = AssetModel.__table__.columns["created_at"]
        assert not col.nullable


class TestAssetModelIndexes:
    def test_hostname_is_indexed(self) -> None:
        idx_names = {i.name for i in AssetModel.__table__.indexes}
        matching = [n for n in idx_names if "hostname" in n]
        assert len(matching) >= 1

    def test_ip_address_is_indexed(self) -> None:
        idx_names = {i.name for i in AssetModel.__table__.indexes}
        matching = [n for n in idx_names if "ip_address" in n]
        assert len(matching) >= 1


# ===========================================================================
# Relationships
# ===========================================================================


class TestRelationships:
    def test_scan_has_findings_relationship(self) -> None:
        rels = {r.key for r in ScanModel.__mapper__.relationships}
        assert "findings" in rels

    def test_scan_has_reports_relationship(self) -> None:
        rels = {r.key for r in ScanModel.__mapper__.relationships}
        assert "reports" in rels

    def test_finding_has_scan_relationship(self) -> None:
        rels = {r.key for r in FindingModel.__mapper__.relationships}
        assert "scan" in rels

    def test_finding_cascade_delete_orphan(self) -> None:
        rel = ScanModel.__mapper__.relationships["findings"]
        assert rel.cascade.delete_orphan

    def test_report_has_scan_relationship(self) -> None:
        rels = {r.key for r in ReportModel.__mapper__.relationships}
        assert "scan" in rels

    def test_report_cascade_delete_orphan(self) -> None:
        rel = ScanModel.__mapper__.relationships["reports"]
        assert rel.cascade.delete_orphan

    def test_asset_has_findings_relationship(self) -> None:
        rels = {r.key for r in AssetModel.__mapper__.relationships}
        assert "findings" in rels


# ===========================================================================
# SQLite in-memory round-trip
# ===========================================================================


class TestSqliteRoundTrip:
    def test_create_scan_and_child_finding(self, session: Session) -> None:
        scan = ScanModel(
            id="scan-1",
            target="example.com",
            status="COMPLETED",
            created_at=datetime.now(UTC).isoformat(),
            completed_at=datetime.now(UTC).isoformat(),
            scanner_count=2,
        )
        finding = FindingModel(
            id="find-1",
            scan_id="scan-1",
            title="Open Port 80",
            description="HTTP service detected",
            severity="MEDIUM",
            scanner="nmap",
            created_at=datetime.now(UTC).isoformat(),
        )
        session.add(scan)
        session.add(finding)
        session.commit()

        loaded = session.get(ScanModel, "scan-1")
        assert loaded is not None
        assert loaded.target == "example.com"
        assert len(loaded.findings) == 1
        assert loaded.findings[0].title == "Open Port 80"

    def test_create_scan_and_report(self, session: Session) -> None:
        scan = ScanModel(
            id="scan-2",
            target="test.com",
            status="COMPLETED",
            created_at=datetime.now(UTC).isoformat(),
        )
        report = ReportModel(
            id="rpt-1",
            scan_id="scan-2",
            format="pdf",
            created_at=datetime.now(UTC).isoformat(),
            content="%PDF mock content",
        )
        session.add(scan)
        session.add(report)
        session.commit()

        loaded = session.get(ScanModel, "scan-2")
        assert len(loaded.reports) == 1
        assert loaded.reports[0].format == "pdf"

    def test_create_job(self, session: Session) -> None:
        job = JobModel(
            id="job-1",
            status="PENDING",
            target="example.com",
            created_at=datetime.now(UTC).isoformat(),
            updated_at=datetime.now(UTC).isoformat(),
        )
        session.add(job)
        session.commit()

        loaded = session.get(JobModel, "job-1")
        assert loaded.status == "PENDING"
        assert loaded.target == "example.com"

    def test_create_asset(self, session: Session) -> None:
        asset = AssetModel(
            id="asset-1",
            hostname="web01.example.com",
            ip_address="10.0.0.1",
            operating_system="Linux 6.8",
            owner="security-team",
            criticality="HIGH",
            created_at=datetime.now(UTC).isoformat(),
        )
        session.add(asset)
        session.commit()

        loaded = session.get(AssetModel, "asset-1")
        assert loaded.hostname == "web01.example.com"
        assert loaded.criticality == "HIGH"

    def test_scan_delete_cascades_to_findings(self, session: Session) -> None:
        scan = ScanModel(
            id="scan-3",
            target="example.com",
            status="COMPLETED",
            created_at=datetime.now(UTC).isoformat(),
        )
        finding = FindingModel(
            id="find-2",
            scan_id="scan-3",
            title="Vuln",
            description="desc",
            severity="HIGH",
            created_at=datetime.now(UTC).isoformat(),
        )
        session.add(scan)
        session.add(finding)
        session.commit()

        session.delete(scan)
        session.commit()

        assert session.get(FindingModel, "find-2") is None

    def test_asset_with_findings(self, session: Session) -> None:
        scan = ScanModel(
            id="scan-4",
            target="example.com",
            status="COMPLETED",
            created_at=datetime.now(UTC).isoformat(),
        )
        asset = AssetModel(
            id="asset-2",
            hostname="db01.example.com",
            created_at=datetime.now(UTC).isoformat(),
        )
        finding = FindingModel(
            id="find-3",
            scan_id="scan-4",
            title="Open Database Port",
            description="MySQL on 3306",
            severity="HIGH",
            asset_id="asset-2",
            created_at=datetime.now(UTC).isoformat(),
        )
        session.add_all([scan, asset, finding])
        session.commit()

        loaded_asset = session.get(AssetModel, "asset-2")
        assert len(loaded_asset.findings) == 1
        assert loaded_asset.findings[0].title == "Open Database Port"


# ===========================================================================
# Metadata creation
# ===========================================================================


class TestMetadataCreation:
    def test_all_new_tables_created(self, engine) -> None:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        for name in ("scan_results", "scan_findings", "scan_reports", "scan_jobs", "assets"):
            assert name in tables, f"Table {name} was not created"
