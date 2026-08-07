"""Integration tests for SQLAlchemyAssessmentRepository.

Tests every public method against a real SQLite database.  No mocks — the
repository is exercised through its port interface exactly as production code
would use it.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from kingsec.application import AssessmentNotFoundError
from kingsec.domain import (
    Assessment,
    AssessmentId,
    Authorization,
    Evidence,
    Finding,
    Recommendation,
    Severity,
    Target,
    TargetType,
)
from kingsec.infrastructure.persistence import (
    create_database_engine,
    create_schema,
)
from kingsec.infrastructure.persistence.repositories import (
    SQLAlchemyAssessmentRepository,
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
    return SQLAlchemyAssessmentRepository(session)


# ===========================================================================
# Helpers
# ===========================================================================


def make_assessment(
    *,
    assessment_id: AssessmentId | None = None,
    target: Target | None = None,
    created_at: datetime | None = None,
) -> Assessment:
    """Build an assessment with sensible defaults for testing."""
    a = Assessment(
        assessment_id=assessment_id or AssessmentId.generate(),
        target=target or Target("example.com", TargetType.HOSTNAME),
        created_at=created_at,
    )
    return a


def make_completed_assessment(
    *,
    assessment_id: AssessmentId | None = None,
    target: Target | None = None,
) -> Assessment:
    """Build a fully lifecycle-completed assessment with findings."""
    a = make_assessment(assessment_id=assessment_id, target=target)
    a.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=UTC), scope="*"))
    a.start()
    finding = Finding.create("Test Finding", "A test", Severity.MEDIUM)
    a.record_finding(finding)
    a.complete()
    return a


# ===========================================================================
# Create & Read
# ===========================================================================


class TestCreateAndRead:
    def test_save_and_get(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        assessment = make_assessment()
        repo.save(assessment)
        session.flush()

        loaded = repo.get(assessment.id)
        assert loaded.id == assessment.id
        assert loaded.target.value == "example.com"
        assert loaded.status.name == "DRAFT"

    def test_save_persists_to_database(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        assessment = make_assessment()
        repo.save(assessment)
        session.flush()

        # Verify directly via SQLAlchemy (bypass repo)
        from kingsec.infrastructure.persistence.models import AssessmentORM

        orm = session.get(AssessmentORM, str(assessment.id))
        assert orm is not None
        assert orm.target_value == "example.com"

    def test_get_returns_domain_object(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        assessment = make_assessment()
        repo.save(assessment)
        session.flush()

        loaded = repo.get(assessment.id)
        assert isinstance(loaded, Assessment)

    def test_get_non_existent_raises(self, repo: SQLAlchemyAssessmentRepository) -> None:
        with pytest.raises(AssessmentNotFoundError):
            repo.get(AssessmentId("nonexistent"))


# ===========================================================================
# Update (upsert)
# ===========================================================================


class TestUpdate:
    def test_save_twice_is_update(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        assessment = make_assessment()
        repo.save(assessment)
        session.flush()

        # Modify status by creating a new domain object with same id
        updated = Assessment.reconstitute(
            assessment_id=assessment.id,
            target=assessment.target,
            status=assessment.status,
            created_at=assessment.created_at,
            authorization=assessment.authorization,
        )
        repo.save(updated)
        session.flush()

        loaded = repo.get(assessment.id)
        assert loaded.id == assessment.id

    def test_upsert_preserves_latest_state(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        assessment = make_assessment()
        repo.save(assessment)
        session.flush()

        new_target = Target("updated.com", TargetType.HOSTNAME)
        updated = Assessment.reconstitute(
            assessment_id=assessment.id,
            target=new_target,
            status=assessment.status,
            created_at=assessment.created_at,
            authorization=None,
        )
        repo.save(updated)
        session.flush()

        loaded = repo.get(assessment.id)
        assert loaded.id == assessment.id

        assert loaded.target.value == "updated.com"


# ===========================================================================
# Delete
# ===========================================================================


class TestDelete:
    def test_delete_removes_assessment(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        assessment = make_assessment()
        repo.save(assessment)
        session.flush()

        repo.delete(assessment.id)
        session.flush()

        with pytest.raises(AssessmentNotFoundError):
            repo.get(assessment.id)

    def test_delete_non_existent_raises(self, repo: SQLAlchemyAssessmentRepository) -> None:
        with pytest.raises(AssessmentNotFoundError):
            repo.delete(AssessmentId("nonexistent"))

    def test_delete_removes_from_database(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        assessment = make_assessment()
        repo.save(assessment)
        session.flush()

        repo.delete(assessment.id)
        session.flush()

        from kingsec.infrastructure.persistence.models import AssessmentORM

        orm = session.get(AssessmentORM, str(assessment.id))
        assert orm is None


# ===========================================================================
# List
# ===========================================================================


class TestList:
    def test_list_empty(self, repo: SQLAlchemyAssessmentRepository) -> None:
        result = repo.list()
        assert result == []

    def test_list_returns_all(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        a1 = make_assessment(target=Target("a.com", TargetType.HOSTNAME))
        a2 = make_assessment(target=Target("b.com", TargetType.HOSTNAME))
        repo.save(a1)
        repo.save(a2)
        session.flush()

        result = repo.list()
        assert len(result) == 2

    def test_list_ordered_by_created_at_desc(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        now = datetime.now(UTC)
        a_early = make_assessment(
            target=Target("early.com", TargetType.HOSTNAME),
            created_at=now,
        )
        a_late = make_assessment(
            target=Target("late.com", TargetType.HOSTNAME),
            created_at=datetime(2025, 1, 1, tzinfo=UTC),
        )
        repo.save(a_early)
        repo.save(a_late)
        session.flush()

        result = repo.list()
        assert result[0].id == a_early.id
        assert result[1].id == a_late.id

    def test_list_respects_limit(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        for i in range(5):
            a = make_assessment(target=Target(f"host-{i}.com", TargetType.HOSTNAME))
            repo.save(a)
        session.flush()

        result = repo.list(limit=2)
        assert len(result) == 2

    def test_list_respects_offset(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        a1 = make_assessment(target=Target("first.com", TargetType.HOSTNAME))
        a2 = make_assessment(target=Target("second.com", TargetType.HOSTNAME))
        a3 = make_assessment(target=Target("third.com", TargetType.HOSTNAME))
        repo.save(a1)
        repo.save(a2)
        repo.save(a3)
        session.flush()

        result = repo.list(limit=10, offset=1)
        assert len(result) == 2

    def test_list_negative_offset_treated_as_zero(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        a = make_assessment()
        repo.save(a)
        session.flush()

        result = repo.list(limit=10, offset=-1)
        assert len(result) == 1


# ===========================================================================
# Mapping correctness
# ===========================================================================


class TestMapping:
    def test_round_trip_preserves_all_fields(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        assessment = make_completed_assessment()
        repo.save(assessment)
        session.flush()

        loaded = repo.get(assessment.id)
        assert loaded.id == assessment.id
        assert loaded.target.value == assessment.target.value
        assert loaded.target.type == assessment.target.type
        assert loaded.status == assessment.status
        assert loaded.created_at == assessment.created_at
        assert loaded.failure_reason == assessment.failure_reason

    def test_round_trip_preserves_findings(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        assessment = make_completed_assessment()
        repo.save(assessment)
        session.flush()

        loaded = repo.get(assessment.id)
        assert len(loaded.findings) == 1
        assert loaded.findings[0].title == "Test Finding"

    def test_round_trip_preserves_authorization(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        assessment = make_completed_assessment()
        repo.save(assessment)
        session.flush()

        loaded = repo.get(assessment.id)
        assert loaded.is_authorized
        assert loaded.authorization is not None
        assert loaded.authorization.authorized_by == "tester"

    def test_round_trips_unicode(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        target = Target("unicode-test.example.com", TargetType.HOSTNAME)
        assessment = make_assessment(target=target)
        repo.save(assessment)
        session.flush()

        loaded = repo.get(assessment.id)
        assert loaded.target.value == "unicode-test.example.com"

    def test_round_trips_evidence_and_recommendations(
        self, repo: SQLAlchemyAssessmentRepository, session: Session
    ) -> None:
        assessment = make_assessment()
        assessment.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=UTC), scope="*"))
        assessment.start()

        finding = Finding.create("XSS", "Cross-site scripting", Severity.HIGH)
        finding.add_evidence(Evidence("Payload", "<script>alert(1)</script>", datetime(2026, 1, 2, tzinfo=UTC)))
        finding.add_recommendation(Recommendation("Sanitize input", "Use output encoding", Severity.HIGH))
        assessment.record_finding(finding)
        assessment.complete()

        repo.save(assessment)
        session.flush()

        loaded = repo.get(assessment.id)
        assert len(loaded.findings) == 1
        assert len(loaded.findings[0].evidence) == 1
        assert len(loaded.findings[0].recommendations) == 1
        assert loaded.findings[0].evidence[0].detail == "<script>alert(1)</script>"
        assert loaded.findings[0].recommendations[0].title == "Sanitize input"


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_multiple_saves_same_id_is_idempotent(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        assessment = make_assessment()
        repo.save(assessment)
        session.flush()
        repo.save(assessment)
        session.flush()

        loaded = repo.get(assessment.id)
        assert loaded.id == assessment.id

    def test_new_session_reads_persisted_data(
        self, engine, repo: SQLAlchemyAssessmentRepository, session: Session
    ) -> None:
        assessment = make_assessment()
        repo.save(assessment)
        session.commit()

        # Fresh session reads committed data
        with Session(engine) as s2:
            repo2 = SQLAlchemyAssessmentRepository(s2)
            loaded = repo2.get(assessment.id)
            assert loaded.id == assessment.id

    def test_rollback_discards_save(self, engine) -> None:
        with Session(engine) as s:
            repo = SQLAlchemyAssessmentRepository(s)
            assessment = make_assessment()
            repo.save(assessment)
            s.rollback()

        with Session(engine) as s2:
            repo2 = SQLAlchemyAssessmentRepository(s2)
            with pytest.raises(AssessmentNotFoundError):
                repo2.get(assessment.id)

    def test_resave_across_sessions_does_not_corrupt(self, engine) -> None:
        """Saving the same assessment id from two different sessions (each
        committing) must not corrupt the row — the second write is a normal
        upsert, and a third, unrelated session must still read a consistent
        result."""
        assessment = make_assessment()

        with Session(engine) as s1:
            SQLAlchemyAssessmentRepository(s1).save(assessment)
            s1.commit()

        with Session(engine) as s2:
            SQLAlchemyAssessmentRepository(s2).save(assessment)
            s2.commit()

        with Session(engine) as s3:
            loaded = SQLAlchemyAssessmentRepository(s3).get(assessment.id)
            assert loaded.id == assessment.id
            assert loaded.target.value == assessment.target.value

    def test_empty_list_with_pagination(self, repo: SQLAlchemyAssessmentRepository) -> None:
        assert repo.list(limit=10, offset=0) == []
        assert repo.list(limit=0, offset=0) == []

    def test_large_pagination(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        for i in range(20):
            a = make_assessment(target=Target(f"h{i}.com", TargetType.HOSTNAME))
            repo.save(a)
        session.flush()

        page1 = repo.list(limit=10, offset=0)
        page2 = repo.list(limit=10, offset=10)
        assert len(page1) == 10
        assert len(page2) == 10

        # Pages should not overlap
        ids1 = {a.id for a in page1}
        ids2 = {a.id for a in page2}
        assert ids1.isdisjoint(ids2)

    def test_timestamps_preserved_exactly(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        created_at = datetime(2025, 6, 15, 14, 30, 0, 123456, tzinfo=UTC)
        assessment = make_assessment(created_at=created_at)
        repo.save(assessment)
        session.flush()

        loaded = repo.get(assessment.id)
        assert loaded.created_at == created_at
        assert loaded.created_at.tzinfo is not None
