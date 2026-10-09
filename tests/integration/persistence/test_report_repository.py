"""Integration tests for SQLAlchemyReportRepository.

Exercises every public method against a real SQLite database.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from kingsec.application import (
    ReportNotFoundError,
)
from kingsec.domain import (
    Assessment,
    AssessmentId,
    Authorization,
    Finding,
    Report,
    Severity,
    SeverityDemotionReason,
    Target,
    TargetType,
)
from kingsec.infrastructure.persistence import (
    create_database_engine,
    create_schema,
)
from kingsec.infrastructure.persistence.repositories import (
    SQLAlchemyAssessmentRepository,
    SQLAlchemyReportRepository,
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
    return SQLAlchemyReportRepository(session)


# ===========================================================================
# Helpers
# ===========================================================================


def make_report(
    session: Session,
    assessment_id: AssessmentId | None = None,
    *,
    generated_at: datetime | None = None,
) -> Report:
    """Build a Report from a completed assessment, and durably persist
    that assessment first (KSEC-110-01: reports.assessment_id now has a
    real FK to assessments.id, matching what GenerateReport always does
    in production - a report is only ever derived from an already-
    persisted, COMPLETED Assessment, never a purely in-memory one)."""
    a_id = assessment_id or AssessmentId.generate()
    target = Target("example.com", TargetType.HOSTNAME)
    assessment = Assessment(a_id, target)
    assessment.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=UTC), scope="*"))
    assessment.start()

    finding = Finding.create("XSS", "Cross-site scripting", Severity.HIGH)
    finding.confirm()
    assessment.record_finding(finding)
    assessment.record_finding(Finding.create("Info", "TLS version", Severity.INFORMATIONAL))
    assessment.complete()

    SQLAlchemyAssessmentRepository(session).save(assessment)
    session.flush()

    return Report.from_assessment(assessment, generated_at=generated_at)


# ===========================================================================
# Save & Get
# ===========================================================================


class TestSaveAndGet:
    def test_save_and_get(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report(session)
        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert loaded.assessment_id == report.assessment_id
        assert loaded.target == str(Target("example.com", TargetType.HOSTNAME))

    def test_get_returns_domain_object(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report(session)
        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert isinstance(loaded, Report)

    def test_get_non_existent_raises(self, repo: SQLAlchemyReportRepository) -> None:
        with pytest.raises(ReportNotFoundError):
            repo.get(AssessmentId("nonexistent"))

    def test_save_persists_to_database(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report(session)
        repo.save(report)
        session.flush()

        from kingsec.infrastructure.persistence.models import ReportORM

        orm = session.get(ReportORM, report.assessment_id)
        assert orm is not None
        assert orm.target == str(Target("example.com", TargetType.HOSTNAME))


# ===========================================================================
# Update / Overwrite
# ===========================================================================


class TestUpdate:
    def test_save_twice_overwrites(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report(session)
        repo.save(report)
        session.flush()

        # Save again with different verdict
        modified = Report(
            assessment_id=report.assessment_id,
            target=report.target,
            generated_at=report.generated_at,
            verdict=report.verdict,
            entries=report.entries,
            severity_counts=report.severity_counts,
        )
        repo.save(modified)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert loaded.assessment_id == report.assessment_id
        assert loaded.target == str(Target("example.com", TargetType.HOSTNAME))

    def test_overwrite_new_target(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report(session)
        repo.save(report)
        session.flush()

        overwritten = Report(
            assessment_id=report.assessment_id,
            target="updated.com",
            generated_at=report.generated_at,
            verdict=report.verdict,
            entries=report.entries,
            severity_counts=report.severity_counts,
        )
        repo.save(overwritten)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert loaded.target == "updated.com"


# ===========================================================================
# Mapping correctness
# ===========================================================================


class TestMapping:
    def test_round_trip_preserves_verdict(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report(session)
        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert loaded.verdict.action_required == report.verdict.action_required
        assert loaded.verdict.headline == report.verdict.headline

    def test_round_trip_preserves_entries(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report(session)
        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert len(loaded.entries) == len(report.entries)
        assert loaded.entries[0].title == report.entries[0].title

    def test_round_trip_preserves_severity_demotion_metadata(
        self, repo: SQLAlchemyReportRepository, session: Session
    ) -> None:
        # Phase 2B-c Priority 1b: this is the Report/JSON-entries path (what
        # the rendered PDF and API actually read) - complements the
        # Finding/SQL-column round trip in test_assessment_repository.py.
        a_id = AssessmentId.generate()
        target = Target("example.com", TargetType.HOSTNAME)
        assessment = Assessment(a_id, target)
        assessment.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=UTC), scope="*"))
        assessment.start()
        assessment.record_finding(
            Finding.create(
                "HTTP 200 - /.env",
                "generic catch-all response",
                Severity.LOW,
                original_severity=Severity.HIGH,
                demotion_reason=SeverityDemotionReason.CONTENT_TYPE_MISMATCH,
            )
        )
        assessment.complete()
        SQLAlchemyAssessmentRepository(session).save(assessment)
        session.flush()
        report = Report.from_assessment(assessment)

        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        entry = loaded.entries[0]
        assert entry.severity == Severity.LOW
        assert entry.original_severity == Severity.HIGH
        assert entry.demotion_reason == SeverityDemotionReason.CONTENT_TYPE_MISMATCH

    def test_round_trip_preserves_severity_counts(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report(session)
        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert len(loaded.severity_counts) == len(report.severity_counts)
        for (sev_a, cnt_a), (sev_b, cnt_b) in zip(loaded.severity_counts, report.severity_counts, strict=False):
            assert sev_a == sev_b
            assert cnt_a == cnt_b

    def test_round_trip_preserves_authorization_metadata(
        self, repo: SQLAlchemyReportRepository, session: Session
    ) -> None:
        report = make_report(session)
        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert loaded.authorized_by == "tester"
        assert loaded.scope == "*"

    def test_round_trip_preserves_ai_explanations(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report(session)
        enriched_entries = tuple(
            dataclasses.replace(e, ai_explanation=f"Business risk for {e.title}") for e in report.entries
        )
        enriched = dataclasses.replace(report, entries=enriched_entries, ai_enabled=True)
        repo.save(enriched)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert loaded.ai_enabled is True
        assert loaded.entries[0].ai_explanation == f"Business risk for {report.entries[0].title}"

    def test_report_without_ai_defaults_to_disabled(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report(session)
        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert loaded.ai_enabled is False
        assert all(e.ai_explanation is None for e in loaded.entries)

    def test_round_trip_preserves_generated_at(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        generated_at = datetime(2025, 6, 15, 14, 30, 0, 123456, tzinfo=UTC)
        report = make_report(session, generated_at=generated_at)
        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert loaded.generated_at == generated_at
        assert loaded.generated_at.tzinfo is not None


# ===========================================================================
# Edge cases
# ===========================================================================


class TestScoreVersion:
    """Phase 2C Step 2: a report is an immutable snapshot - one persisted
    with score_version="v1" (the deprecated linear-deduction formula)
    must keep reporting its v1 score forever, on both the detail path
    (Report.executive_score) and the list-view projection
    (SQLAlchemyReportRepository._compute_score), never be silently
    rescored under v2 just because that's now the default formula."""

    def test_new_report_defaults_to_v2(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report(session)
        assert report.score_version == "v2"
        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert loaded.score_version == "v2"

    def test_v1_report_loaded_from_db_still_reports_v1_score(
        self, repo: SQLAlchemyReportRepository, session: Session
    ) -> None:
        report = dataclasses.replace(make_report(session), score_version="v1")
        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert loaded.score_version == "v1"

        from kingsec.domain.report import compute_executive_score, compute_executive_score_v1

        assert loaded.executive_score == compute_executive_score_v1(loaded.severity_counts)
        assert loaded.executive_score != compute_executive_score(loaded.severity_counts)

    def test_list_view_score_agrees_with_v1_detail_score(
        self, repo: SQLAlchemyReportRepository, session: Session
    ) -> None:
        # The historical bug this closes: the list-view projection had its
        # own independent _compute_score() call site that always used
        # whichever formula was current, disagreeing with the detail view
        # for any v1-scored row.
        report = dataclasses.replace(make_report(session), score_version="v1")
        repo.save(report)
        session.flush()

        detail = repo.get(AssessmentId(report.assessment_id))
        projections, _ = repo.list(is_admin=True)
        listed = next(p for p in projections if p.assessment_id == report.assessment_id)
        assert listed.executive_score == detail.executive_score


class TestEdgeCases:
    def test_save_and_get_unicode(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        a_id = AssessmentId.generate()
        assessment = Assessment(a_id, Target("unicode-test.example.com", TargetType.HOSTNAME))
        assessment.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=UTC), scope="*"))
        assessment.start()
        assessment.record_finding(Finding.create("Öné", "Desc", Severity.LOW))
        assessment.complete()
        SQLAlchemyAssessmentRepository(session).save(assessment)
        session.flush()
        report = Report.from_assessment(assessment)

        repo.save(report)
        session.flush()

        loaded = repo.get(AssessmentId(report.assessment_id))
        assert "unicode-test.example.com" in loaded.target or "Öné" in loaded.entries[0].title

    def test_multiple_reports(self, repo: SQLAlchemyReportRepository, session: Session) -> None:
        r1 = make_report(session, AssessmentId.generate())
        r2 = make_report(session, AssessmentId.generate())
        repo.save(r1)
        repo.save(r2)
        session.flush()

        loaded1 = repo.get(AssessmentId(r1.assessment_id))
        loaded2 = repo.get(AssessmentId(r2.assessment_id))
        assert loaded1.assessment_id != loaded2.assessment_id

    def test_rollback_discards_save(self, engine) -> None:
        with Session(engine) as s:
            repo = SQLAlchemyReportRepository(s)
            report = make_report(s)
            repo.save(report)
            s.rollback()

        with Session(engine) as s2:
            repo2 = SQLAlchemyReportRepository(s2)
            with pytest.raises(ReportNotFoundError):
                repo2.get(AssessmentId(report.assessment_id))

    def test_new_session_reads_committed(self, engine, repo: SQLAlchemyReportRepository, session: Session) -> None:
        report = make_report(session)
        repo.save(report)
        session.commit()

        with Session(engine) as s2:
            repo2 = SQLAlchemyReportRepository(s2)
            loaded = repo2.get(AssessmentId(report.assessment_id))
            assert loaded.assessment_id == report.assessment_id

    def test_empty_database_raises_on_get(self, repo: SQLAlchemyReportRepository) -> None:
        with pytest.raises(ReportNotFoundError):
            repo.get(AssessmentId("does-not-exist"))


class TestListReports:
    def test_searches_target_assessment_id_and_verdict(
        self, repo: SQLAlchemyReportRepository, session: Session
    ) -> None:
        report = make_report(session)
        report = dataclasses.replace(
            report,
            target="search-target.example.com",
            verdict=dataclasses.replace(report.verdict, headline="Distinct verdict phrase"),
        )
        repo.save(report)
        session.flush()

        for query in ("search-target", report.assessment_id[-8:], "distinct VERDICT"):
            items, total = repo.list(search=query, is_admin=True)
            assert total == 1
            assert [item.assessment_id for item in items] == [report.assessment_id]

    def test_search_treats_sql_wildcards_as_literal(
        self, repo: SQLAlchemyReportRepository, session: Session
    ) -> None:
        report = make_report(session)
        repo.save(report)
        session.flush()

        assert repo.list(search="%", is_admin=True)[1] == 0
        assert repo.list(search="_", is_admin=True)[1] == 0

    def test_orders_severity_by_risk_not_alphabetically(
        self, repo: SQLAlchemyReportRepository, session: Session
    ) -> None:
        high = make_report(session)
        low = dataclasses.replace(
            make_report(session),
            verdict=dataclasses.replace(
                high.verdict,
                highest_severity=Severity.LOW,
                headline="Low-risk issues found — review advised.",
            ),
        )
        repo.save(low)
        repo.save(high)
        session.flush()

        items, _ = repo.list(
            order_by="verdict_highest_severity", order_dir="desc", is_admin=True
        )
        assert [item.verdict_highest_severity for item in items] == ["HIGH", "LOW"]
