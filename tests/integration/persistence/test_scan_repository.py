"""Integration tests for SQLAlchemyScanRepository.

Exercises every ScanRepositoryPort method against a real SQLite database.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy.orm import Session

from kingsec.application import AssessmentNotFoundError
from kingsec.domain import (
    Finding,
    ScannerId,
    ScannerResult,
    Severity,
)
from kingsec.infrastructure.persistence import (
    create_database_engine,
    create_schema,
)
from kingsec.infrastructure.persistence.repositories import (
    SQLAlchemyScanRepository,
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
        s.rollback()


@pytest.fixture
def repo(session):
    return SQLAlchemyScanRepository(session)


# ===========================================================================
# Helpers
# ===========================================================================


def make_result(
    *,
    scanner_id: str = "nmap",
    num_findings: int = 1,
) -> ScannerResult:
    """Build a ScannerResult with sensible defaults."""
    findings = tuple(
        Finding.create(f"Vuln-{i}", f"Description {i}", Severity.MEDIUM)
        for i in range(num_findings)
    )
    return ScannerResult(
        scanner_id=ScannerId(scanner_id),
        findings=findings,
        raw_output="nmap output here",
        duration_seconds=12.5,
        scanner_version="1.0.0",
        warnings=("rate limited",),
    )


# ===========================================================================
# Save & Get
# ===========================================================================


class TestSaveAndGet:
    def test_save_and_get(self, repo: SQLAlchemyScanRepository, session: Session) -> None:
        result = make_result()
        repo.save("scan-1", result)
        session.flush()

        loaded = repo.get("scan-1")
        assert loaded.scanner_id == result.scanner_id

    def test_get_returns_domain_object(self, repo: SQLAlchemyScanRepository, session: Session) -> None:
        result = make_result()
        repo.save("scan-1", result)
        session.flush()

        loaded = repo.get("scan-1")
        assert isinstance(loaded, ScannerResult)

    def test_get_non_existent_raises(self, repo: SQLAlchemyScanRepository) -> None:
        with pytest.raises(AssessmentNotFoundError):
            repo.get("nonexistent")

    def test_save_persists_to_database(self, repo: SQLAlchemyScanRepository, session: Session) -> None:
        result = make_result()
        repo.save("scan-1", result)
        session.flush()

        from kingsec.infrastructure.persistence.models import ScanModel
        orm = session.get(ScanModel, "scan-1")
        assert orm is not None
        assert orm.id == "scan-1"


# ===========================================================================
# Exists
# ===========================================================================


class TestExists:
    def test_exists_returns_true_when_present(self, repo: SQLAlchemyScanRepository, session: Session) -> None:
        repo.save("scan-1", make_result())
        session.flush()
        assert repo.exists("scan-1") is True

    def test_exists_returns_false_when_absent(self, repo: SQLAlchemyScanRepository) -> None:
        assert repo.exists("nonexistent") is False

    def test_exists_after_delete(self, repo: SQLAlchemyScanRepository, session: Session) -> None:
        repo.save("scan-1", make_result())
        session.flush()
        repo.delete("scan-1")
        session.flush()
        assert repo.exists("scan-1") is False


# ===========================================================================
# Delete
# ===========================================================================


class TestDelete:
    def test_delete_removes_scan(self, repo: SQLAlchemyScanRepository, session: Session) -> None:
        repo.save("scan-1", make_result())
        session.flush()
        repo.delete("scan-1")
        session.flush()
        assert repo.exists("scan-1") is False

    def test_delete_non_existent_raises(self, repo: SQLAlchemyScanRepository) -> None:
        with pytest.raises(AssessmentNotFoundError):
            repo.delete("nonexistent")

    def test_delete_cascades_to_findings(self, repo: SQLAlchemyScanRepository, session: Session) -> None:
        result = make_result(num_findings=2)
        repo.save("scan-1", result)
        session.flush()

        from kingsec.infrastructure.persistence.models import FindingModel
        before = session.execute(
            __import__("sqlalchemy").select(FindingModel).where(FindingModel.scan_id == "scan-1")
        ).scalars().all()
        assert len(before) == 2

        repo.delete("scan-1")
        session.flush()

        after = session.execute(
            __import__("sqlalchemy").select(FindingModel).where(FindingModel.scan_id == "scan-1")
        ).scalars().all()
        assert len(after) == 0


# ===========================================================================
# Overwrite (upsert)
# ===========================================================================


class TestOverwrite:
    def test_save_twice_overwrites(self, repo: SQLAlchemyScanRepository, session: Session) -> None:
        result1 = make_result(scanner_id="nmap")
        repo.save("scan-1", result1)
        session.flush()

        result2 = make_result(scanner_id="nuclei")
        repo.save("scan-1", result2)
        session.flush()

        loaded = repo.get("scan-1")
        assert loaded.scanner_id == ScannerId("nuclei")

    def test_overwrite_replaces_findings(self, repo: SQLAlchemyScanRepository, session: Session) -> None:
        result1 = make_result(num_findings=3)
        repo.save("scan-1", result1)
        session.flush()

        result2 = make_result(num_findings=1)
        repo.save("scan-1", result2)
        session.flush()

        loaded = repo.get("scan-1")
        assert len(loaded.findings) == 1


# ===========================================================================
# Mapping correctness
# ===========================================================================


class TestMapping:
    def test_round_trip_preserves_scanner_id(self, repo: SQLAlchemyScanRepository, session: Session) -> None:
        result = make_result(scanner_id="nuclei")
        repo.save("scan-1", result)
        session.flush()

        loaded = repo.get("scan-1")
        assert loaded.scanner_id == ScannerId("nuclei")

    def test_round_trip_preserves_findings_count(self, repo: SQLAlchemyScanRepository, session: Session) -> None:
        result = make_result(num_findings=5)
        repo.save("scan-1", result)
        session.flush()

        loaded = repo.get("scan-1")
        assert len(loaded.findings) == 5

    def test_round_trip_preserves_finding_titles(self, repo: SQLAlchemyScanRepository, session: Session) -> None:
        finding = Finding.create("SQLi", "SQL injection", Severity.HIGH)
        result = ScannerResult(
            scanner_id=ScannerId("nuclei"),
            findings=(finding,),
            raw_output="",
            duration_seconds=1.0,
        )
        repo.save("scan-1", result)
        session.flush()

        loaded = repo.get("scan-1")
        assert loaded.findings[0].title == "SQLi"
        assert loaded.findings[0].severity == Severity.HIGH

    def test_round_trip_unicode(self, repo: SQLAlchemyScanRepository, session: Session) -> None:
        finding = Finding.create("Öné-Twö", "über description", Severity.LOW)
        result = ScannerResult(
            scanner_id=ScannerId("nmap"),
            findings=(finding,),
            raw_output="",
            duration_seconds=1.0,
        )
        repo.save("scan-1", result)
        session.flush()

        loaded = repo.get("scan-1")
        assert "Öné" in loaded.findings[0].title
        assert "über" in loaded.findings[0].description


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_multiple_scans(self, repo: SQLAlchemyScanRepository, session: Session) -> None:
        repo.save("scan-1", make_result(scanner_id="nmap"))
        repo.save("scan-2", make_result(scanner_id="nuclei"))
        session.flush()

        assert repo.exists("scan-1")
        assert repo.exists("scan-2")
        assert repo.get("scan-1").scanner_id == ScannerId("nmap")
        assert repo.get("scan-2").scanner_id == ScannerId("nuclei")

    def test_rollback_discards_save(self, engine) -> None:
        with Session(engine) as s:
            repo = SQLAlchemyScanRepository(s)
            repo.save("scan-1", make_result())
            s.rollback()

        with Session(engine) as s2:
            repo2 = SQLAlchemyScanRepository(s2)
            assert repo2.exists("scan-1") is False

    def test_new_session_reads_committed(self, engine, repo: SQLAlchemyScanRepository, session: Session) -> None:
        repo.save("scan-1", make_result())
        session.commit()

        with Session(engine) as s2:
            repo2 = SQLAlchemyScanRepository(s2)
            assert repo2.exists("scan-1") is True

    def test_empty_database(self, repo: SQLAlchemyScanRepository) -> None:
        assert repo.exists("anything") is False
        with pytest.raises(AssessmentNotFoundError):
            repo.get("anything")
        with pytest.raises(AssessmentNotFoundError):
            repo.delete("anything")

    def test_save_and_get_no_findings(self, repo: SQLAlchemyScanRepository, session: Session) -> None:
        result = ScannerResult(
            scanner_id=ScannerId("nmap"),
            findings=(),
            raw_output="",
            duration_seconds=0.0,
        )
        repo.save("scan-empty", result)
        session.flush()

        loaded = repo.get("scan-empty")
        assert len(loaded.findings) == 0
