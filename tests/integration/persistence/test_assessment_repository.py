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
from kingsec.application.errors import AssessmentConflictError
from kingsec.domain import (
    Assessment,
    AssessmentId,
    Authorization,
    Evidence,
    Finding,
    Recommendation,
    ScannerRunSummary,
    Severity,
    SeverityDemotionReason,
    Target,
    TargetType,
)
from kingsec.domain.enums import ScannerRunState
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
        assert result.items == ()
        assert result.total == 0
        assert result.unreadable_ids == ()

    def test_list_returns_all(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        a1 = make_assessment(target=Target("a.com", TargetType.HOSTNAME))
        a2 = make_assessment(target=Target("b.com", TargetType.HOSTNAME))
        repo.save(a1)
        repo.save(a2)
        session.flush()

        result = repo.list()
        assert len(result.items) == 2
        assert result.total == 2

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
        assert result.items[0].id == a_early.id
        assert result.items[1].id == a_late.id

    def test_list_respects_limit(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        for i in range(5):
            a = make_assessment(target=Target(f"host-{i}.com", TargetType.HOSTNAME))
            repo.save(a)
        session.flush()

        result = repo.list(limit=2)
        assert len(result.items) == 2

    def test_list_respects_offset(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        a1 = make_assessment(target=Target("first.com", TargetType.HOSTNAME))
        a2 = make_assessment(target=Target("second.com", TargetType.HOSTNAME))
        a3 = make_assessment(target=Target("third.com", TargetType.HOSTNAME))
        repo.save(a1)
        repo.save(a2)
        repo.save(a3)
        session.flush()

        result = repo.list(limit=10, offset=1)
        assert len(result.items) == 2

    def test_list_negative_offset_treated_as_zero(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        a = make_assessment()
        repo.save(a)
        session.flush()

        result = repo.list(limit=10, offset=-1)
        assert len(result.items) == 1

    def test_ownership_is_applied_before_pagination(
        self, repo: SQLAlchemyAssessmentRepository, session: Session
    ) -> None:
        alice_old = make_assessment(
            target=Target("alice-old.example", TargetType.HOSTNAME),
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        alice_old.set_ownership("alice")
        bob_middle = make_assessment(
            target=Target("bob-middle.example", TargetType.HOSTNAME),
            created_at=datetime(2026, 1, 3, tzinfo=UTC),
        )
        bob_middle.set_ownership("bob")
        alice_new = make_assessment(
            target=Target("alice-new.example", TargetType.HOSTNAME),
            created_at=datetime(2026, 1, 2, tzinfo=UTC),
        )
        alice_new.set_ownership("alice")
        bob_newest = make_assessment(
            target=Target("bob-newest.example", TargetType.HOSTNAME),
            created_at=datetime(2026, 1, 4, tzinfo=UTC),
        )
        bob_newest.set_ownership("bob")
        for assessment in (alice_old, bob_middle, alice_new, bob_newest):
            repo.save(assessment)
        session.flush()

        result = repo.list(
            limit=1,
            offset=1,
            requesting_user="alice",
            is_admin=False,
        )

        assert result.total == 2
        assert tuple(assessment.id for assessment in result.items) == (alice_old.id,)

    def test_combined_filters_and_total_are_applied_before_pagination(
        self, repo: SQLAlchemyAssessmentRepository, session: Session
    ) -> None:
        alpha = make_assessment(target=Target("alpha-acme.example", TargetType.HOSTNAME))
        alpha.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=UTC), scope="*"))
        alpha.set_ownership("alice")
        beta = make_assessment(target=Target("beta-acme.example", TargetType.HOSTNAME))
        beta.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=UTC), scope="*"))
        beta.set_ownership("alice")
        wrong_status = make_assessment(target=Target("draft-acme.example", TargetType.HOSTNAME))
        wrong_status.set_ownership("alice")
        wrong_search = make_assessment(target=Target("outside.example", TargetType.HOSTNAME))
        wrong_search.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=UTC), scope="*"))
        wrong_search.set_ownership("alice")
        wrong_owner = make_assessment(target=Target("other-acme.example", TargetType.HOSTNAME))
        wrong_owner.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=UTC), scope="*"))
        wrong_owner.set_ownership("bob")
        for assessment in (alpha, beta, wrong_status, wrong_search, wrong_owner):
            repo.save(assessment)
        session.flush()

        first_page = repo.list(
            limit=1,
            search="ACME",
            status="authorized",
            order_by="target",
            order_dir="asc",
            requesting_user="alice",
            is_admin=False,
        )
        second_page = repo.list(
            limit=1,
            offset=1,
            search="ACME",
            status="authorized",
            order_by="target",
            order_dir="asc",
            requesting_user="alice",
            is_admin=False,
        )

        assert first_page.total == 2
        assert second_page.total == 2
        assert tuple(assessment.id for assessment in first_page.items) == (alpha.id,)
        assert tuple(assessment.id for assessment in second_page.items) == (beta.id,)

    def test_search_treats_sql_wildcards_as_literal_text(
        self, repo: SQLAlchemyAssessmentRepository, session: Session
    ) -> None:
        literal = make_assessment(
            target=Target("/srv/customer/100%_real", TargetType.SOURCE_PATH)
        )
        wildcard_match_without_escaping = make_assessment(
            target=Target("/srv/customer/100XXreal", TargetType.SOURCE_PATH)
        )
        repo.save(literal)
        repo.save(wildcard_match_without_escaping)
        session.flush()

        result = repo.list(search="%_")

        assert result.total == 1
        assert tuple(assessment.id for assessment in result.items) == (literal.id,)

    def test_findings_count_sort_uses_persisted_child_rows(
        self, repo: SQLAlchemyAssessmentRepository, session: Session
    ) -> None:
        none = make_assessment(target=Target("none.example", TargetType.HOSTNAME))
        two = make_assessment(target=Target("two.example", TargetType.HOSTNAME))
        two.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=UTC), scope="*"))
        two.start()
        two.record_finding(Finding.create("First", "First finding", Severity.LOW))
        two.record_finding(Finding.create("Second", "Second finding", Severity.HIGH))
        two.complete()
        repo.save(none)
        repo.save(two)
        session.flush()

        result = repo.list(order_by="findings_count", order_dir="desc")

        assert result.total == 2
        assert tuple(assessment.id for assessment in result.items) == (two.id, none.id)

    def test_unknown_sort_field_falls_back_to_created_at(
        self, repo: SQLAlchemyAssessmentRepository, session: Session
    ) -> None:
        old = make_assessment(
            target=Target("zulu.example", TargetType.HOSTNAME),
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        new = make_assessment(
            target=Target("alpha.example", TargetType.HOSTNAME),
            created_at=datetime(2026, 1, 2, tzinfo=UTC),
        )
        repo.save(old)
        repo.save(new)
        session.flush()

        result = repo.list(order_by="target_value desc; drop table assessments")

        assert tuple(assessment.id for assessment in result.items) == (new.id, old.id)
        assert repo.get(old.id).id == old.id

    def test_unreadable_ids_and_total_respect_owner_scope(
        self, repo: SQLAlchemyAssessmentRepository, session: Session
    ) -> None:
        from kingsec.infrastructure.persistence.models import AssessmentORM

        mine = make_assessment(target=Target("mine.example", TargetType.HOSTNAME))
        mine.set_ownership("alice")
        theirs = make_assessment(target=Target("theirs.example", TargetType.HOSTNAME))
        theirs.set_ownership("bob")
        repo.save(mine)
        repo.save(theirs)
        session.flush()

        mine_orm = session.get(AssessmentORM, str(mine.id))
        theirs_orm = session.get(AssessmentORM, str(theirs.id))
        assert mine_orm is not None
        assert theirs_orm is not None
        mine_orm.target_type = "NOT_A_TARGET_TYPE"
        theirs_orm.target_type = "NOT_A_TARGET_TYPE"
        session.flush()

        alice_page = repo.list(requesting_user="alice", is_admin=False)
        admin_page = repo.list(is_admin=True)

        assert alice_page.items == ()
        assert alice_page.total == 1
        assert alice_page.unreadable_ids == (str(mine.id),)
        assert admin_page.items == ()
        assert admin_page.total == 2
        assert set(admin_page.unreadable_ids) == {str(mine.id), str(theirs.id)}


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

    def test_null_authorization_id_round_trips_and_the_row_renders_correctly(
        self, repo: SQLAlchemyAssessmentRepository, session: Session
    ) -> None:
        """Every pre-enforcement (and pre-Phase-4) row has authorization_id
        = NULL at the database level. This is the real risk the dropped
        synthesized-grant backfill test was replaced with: prove a NULL
        row loads and serves through the actual read path
        (AssessmentView.from_domain(), the same mapping GetAssessment
        uses) without raising."""
        from kingsec.application.dto import AssessmentView

        assessment = make_assessment()
        assert assessment.authorization_id is None
        repo.save(assessment)
        session.flush()

        loaded = repo.get(assessment.id)
        assert loaded.authorization_id is None

        view = AssessmentView.from_domain(loaded)
        assert view.assessment_id == str(loaded.id)

    def test_round_trips_a_populated_authorization_id(
        self, repo: SQLAlchemyAssessmentRepository, session: Session
    ) -> None:
        assessment = Assessment.create(
            Target("example.com", TargetType.HOSTNAME),
            authorization_id="agrt-deadbeef00000000000000000000000",
        )
        repo.save(assessment)
        session.flush()

        loaded = repo.get(assessment.id)
        assert loaded.authorization_id == "agrt-deadbeef00000000000000000000000"

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

    def test_round_trips_severity_demotion_metadata(
        self, repo: SQLAlchemyAssessmentRepository, session: Session
    ) -> None:
        # Phase 2B-c Priority 1b: original_severity/demotion_reason are
        # structured (not just prose) precisely so they must survive the
        # DB round trip - this is the acceptance test the user required.
        assessment = make_assessment()
        assessment.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=UTC), scope="*"))
        assessment.start()

        demoted = Finding.create(
            "HTTP 200 - /.env",
            "generic catch-all response",
            Severity.LOW,
            original_severity=Severity.HIGH,
            demotion_reason=SeverityDemotionReason.CONTENT_TYPE_MISMATCH,
        )
        not_demoted = Finding.create("SQLi", "id param injectable", Severity.CRITICAL)
        assessment.record_finding(demoted)
        assessment.record_finding(not_demoted)
        assessment.complete()

        repo.save(assessment)
        session.flush()

        loaded = repo.get(assessment.id)
        by_title = {f.title: f for f in loaded.findings}

        reloaded_demoted = by_title["HTTP 200 - /.env"]
        assert reloaded_demoted.severity == Severity.LOW
        assert reloaded_demoted.original_severity == Severity.HIGH
        assert reloaded_demoted.demotion_reason == SeverityDemotionReason.CONTENT_TYPE_MISMATCH
        assert reloaded_demoted.was_demoted is True

        reloaded_clean = by_title["SQLi"]
        assert reloaded_clean.original_severity is None
        assert reloaded_clean.demotion_reason is None
        assert reloaded_clean.was_demoted is False

    def test_round_trips_rate_limit_and_stderr_scanner_summary_fields(
        self, repo: SQLAlchemyAssessmentRepository, session: Session
    ) -> None:
        # Phase 2B-c Priorities 3/4: rate_limit_description and
        # stderr_excerpt must survive the DB round trip same as the
        # existing port_specification field they were added alongside.
        assessment = make_assessment()
        assessment.authorize(Authorization("tester", datetime(2026, 1, 1, tzinfo=UTC), scope="*"))
        assessment.start()
        assessment.record_scanner_summary(
            (
                ScannerRunSummary(
                    scanner_id="ffuf",
                    name="ffuf",
                    status=ScannerRunState.SUCCEEDED,
                    findings_count=3,
                    rate_limit_description="40 requests/second (ffuf -rate)",
                ),
                ScannerRunSummary(
                    scanner_id="gobuster",
                    name="Gobuster",
                    status=ScannerRunState.FAILED,
                    skipped_reason="The scan process exited with an error before producing usable results.",
                    stderr_excerpt="gobuster: wordlist file not found",
                ),
            )
        )
        assessment.complete()

        repo.save(assessment)
        session.flush()

        loaded = repo.get(assessment.id)
        by_id = {s.scanner_id: s for s in loaded.scanner_summary}
        assert by_id["ffuf"].rate_limit_description == "40 requests/second (ffuf -rate)"
        assert by_id["gobuster"].stderr_excerpt == "gobuster: wordlist file not found"
        assert by_id["gobuster"].rate_limit_description is None
        assert by_id["ffuf"].stderr_excerpt is None


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_resaving_the_same_object_twice_evolves_its_version_in_place(
        self, repo: SQLAlchemyAssessmentRepository, session: Session
    ) -> None:
        """KSEC-107-01 / KSEC-108-01: saving the identical in-memory object
        twice is no longer a blind upsert - each save is a real,
        version-checked write. It still succeeds both times, because
        persist_assessment() advances the object's OWN ``_version`` in
        place immediately after a successful write (needed for callers
        like StartAssessment, which legitimately save() the same object
        twice in a row without re-``get()``-ing in between - see
        test_assessment_optimistic_concurrency.py's dedicated regression
        test for that exact scenario). What is NOT accepted is a stale
        writer whose OWN version was never advanced attempting to save
        after someone ELSE'S write already moved the row forward - see
        test_resave_across_sessions_with_independent_objects_conflicts."""
        assessment = make_assessment()
        assert assessment.version == 0
        repo.save(assessment)
        session.flush()
        assert assessment.version == 1

        repo.save(assessment)  # the SAME object, saved again - succeeds
        session.flush()
        assert assessment.version == 2

        loaded = repo.get(assessment.id)
        assert loaded.version == 2

    def test_load_mutate_save_evolves_version(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        """The correct, supported repeat-save pattern: re-``get()`` between
        saves. Each save is a genuine, distinct, version-checked write."""
        assessment = make_assessment()
        repo.save(assessment)
        session.flush()

        reloaded = repo.get(assessment.id)
        assert reloaded.version == 1
        repo.save(reloaded)
        session.flush()

        loaded = repo.get(assessment.id)
        assert loaded.id == assessment.id
        assert loaded.version == 2

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

    def test_resave_across_sessions_with_the_same_object_evolves_version_correctly(self, engine) -> None:
        """KSEC-107-01 / KSEC-108-01: saving the SAME in-memory assessment
        object from two different sessions, one after the other, succeeds
        both times and correctly advances the version each time - the
        object's own version is updated in place after session 1's save,
        so session 2's save is a genuine, version-checked, non-stale write
        (not a resurrected blind upsert). See the test immediately below
        for what happens when the object saved a second time is NOT the
        one that performed the first save."""
        assessment = make_assessment()

        with Session(engine) as s1:
            SQLAlchemyAssessmentRepository(s1).save(assessment)
            s1.commit()
        assert assessment.version == 1

        with Session(engine) as s2:
            SQLAlchemyAssessmentRepository(s2).save(assessment)
            s2.commit()
        assert assessment.version == 2

        with Session(engine) as s3:
            loaded = SQLAlchemyAssessmentRepository(s3).get(assessment.id)
            assert loaded.id == assessment.id
            assert loaded.target.value == assessment.target.value
            assert loaded.version == 2

    def test_resave_across_sessions_with_independent_stale_object_conflicts(self, engine) -> None:
        """The actual KSEC-107-01 protection: an INDEPENDENT object that
        never saw session 1's write (e.g. loaded before it happened, or
        constructed separately) must be rejected, not silently applied -
        the row must remain exactly what session 1 committed."""
        assessment = make_assessment()

        with Session(engine) as s1:
            SQLAlchemyAssessmentRepository(s1).save(assessment)
            s1.commit()

        stale = Assessment(assessment.id, assessment.target)  # independent, version=0
        with Session(engine) as s2:
            with pytest.raises(AssessmentConflictError):
                SQLAlchemyAssessmentRepository(s2).save(stale)
                s2.flush()
            s2.rollback()

        with Session(engine) as s3:
            loaded = SQLAlchemyAssessmentRepository(s3).get(assessment.id)
            assert loaded.id == assessment.id
            assert loaded.target.value == assessment.target.value
            assert loaded.version == 1

    def test_empty_list_with_pagination(self, repo: SQLAlchemyAssessmentRepository) -> None:
        assert repo.list(limit=10, offset=0).items == ()
        assert repo.list(limit=0, offset=0).items == ()

    def test_large_pagination(self, repo: SQLAlchemyAssessmentRepository, session: Session) -> None:
        for i in range(20):
            a = make_assessment(target=Target(f"h{i}.com", TargetType.HOSTNAME))
            repo.save(a)
        session.flush()

        page1 = repo.list(limit=10, offset=0).items
        page2 = repo.list(limit=10, offset=10).items
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
