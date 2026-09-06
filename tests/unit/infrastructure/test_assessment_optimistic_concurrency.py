"""KSEC-107-01 / KSEC-108-01: direct, thorough verification of the
Assessment-level optimistic-concurrency primitive itself.

Phase 107 found and deterministically reproduced a lost-update race:
persist_assessment()'s unconditional DELETE-then-INSERT let a stale
writer silently overwrite a newer, real, terminal Assessment. Phase 108
fixes it by giving Assessment a `version` counter (mirroring the already-
proven ScheduleORM/AssessmentExecutionORM idiom) and making the replace
path a single, atomic, conditional `DELETE ... WHERE id = ? AND
version = ?`.

This file tests the primitive directly, at the repository level, real
on-disk SQLite, real transactions, real threads for the multi-writer
races - complementing (not duplicating) test_phase107_duplicate_submission.py
and test_assessment_creation_submission_routes.py, which exercise the fix
through the higher-level SubmitAssessment/HTTP surfaces.
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from kingsec.application.errors import AssessmentConflictError, AssessmentNotFoundError
from kingsec.domain import Authorization, Finding, Severity, Target, TargetType
from kingsec.domain.assessment import Assessment
from kingsec.domain.enums import AssessmentStatus
from kingsec.infrastructure.persistence._legacy_repositories import LegacyAssessmentRepository
from kingsec.infrastructure.persistence.models import AssessmentORM, Base

# ── Fixtures: real on-disk SQLite, with the SAME foreign_keys=ON pragma
# every real engine this project creates enables (database.py) - required
# for ON DELETE CASCADE (findings) to actually fire under the raw Core
# conditional DELETE persist_assessment() now uses. ─────────────────────


def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=10000")
    cursor.close()


@pytest.fixture
def engine(tmp_path: Path):
    db_path = tmp_path / f"phase108-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    event.listen(eng, "connect", _enable_foreign_keys)
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def repo(session_factory) -> LegacyAssessmentRepository:
    return LegacyAssessmentRepository(session_factory)


def _target() -> Target:
    return Target("10.0.0.9", TargetType.IP_ADDRESS)


def _new_authorized_assessment() -> Assessment:
    a = Assessment.create(_target())
    a.authorize(Authorization.grant("pentester@kingusecurity.com", "10.0.0.9"))
    return a


def _finding(title: str = "SQLi") -> Finding:
    return Finding.create(title, "injectable param", Severity.CRITICAL)


# ── Section 7: version semantics ─────────────────────────────────────────


class TestVersionSemantics:
    def test_initial_version_of_a_freshly_created_assessment_is_zero(self) -> None:
        a = Assessment.create(_target())
        assert a.version == 0

    def test_first_successful_persistence_establishes_version_one(
        self, repo: LegacyAssessmentRepository, session_factory
    ) -> None:
        a = _new_authorized_assessment()
        repo.save(a)
        with session_factory() as session:
            row = session.execute(select(AssessmentORM).where(AssessmentORM.id == str(a.id))).scalar_one()
            assert row.version == 1

    def test_loading_returns_the_real_durable_version(self, repo: LegacyAssessmentRepository) -> None:
        a = _new_authorized_assessment()
        repo.save(a)
        loaded = repo.get(a.id)
        assert loaded.version == 1

    def test_each_successful_save_advances_the_durable_version_by_one(self, repo: LegacyAssessmentRepository) -> None:
        a = _new_authorized_assessment()
        repo.save(a)
        v1 = repo.get(a.id)
        assert v1.version == 1

        v1.start()
        repo.save(v1)
        v2 = repo.get(a.id)
        assert v2.version == 2

        v2.complete()
        repo.save(v2)
        v3 = repo.get(a.id)
        assert v3.version == 3

    def test_a_stale_save_does_not_advance_the_durable_version(self, repo: LegacyAssessmentRepository) -> None:
        a = _new_authorized_assessment()
        repo.save(a)
        stale = repo.get(a.id)  # version 1

        fresh = repo.get(a.id)
        fresh.start()
        repo.save(fresh)  # advances to version 2

        with pytest.raises(AssessmentConflictError):
            stale.start()
            repo.save(stale)

        unchanged = repo.get(a.id)
        assert unchanged.version == 2


# ── Section 20: load -> mutate -> save contract ─────────────────────────


class TestLoadMutateSaveContract:
    def test_reusing_the_same_object_across_two_sequential_saves_evolves_version_in_place(
        self, repo: LegacyAssessmentRepository
    ) -> None:
        """KSEC-108-01 regression: StartAssessment.execute() (the
        synchronous use case) loads ONE Assessment object, saves it once
        for RUNNING, then mutates and saves the SAME object again later for
        COMPLETED/FAILED - never re-``get()``-ing in between. Discovered
        via the full pytest suite: 6 pre-existing "full vertical slice"
        integration tests that exercise this exact path started failing
        with AssessmentConflictError on the SECOND save, because the
        object's version was captured once at load time and never advanced
        after the first successful save. Fixed by having
        persist_assessment() bump the passed-in object's own version in
        place on success (see its docstring) - this test proves that
        directly, independent of StartAssessment itself."""
        a = _new_authorized_assessment()
        repo.save(a)
        reused = repo.get(a.id)
        assert reused.version == 1

        reused.start()
        repo.save(reused)
        assert reused.version == 2, "the SAME object's version must advance after its own successful save"

        reused.record_finding(_finding())
        reused.complete()
        repo.save(reused)  # must NOT raise AssessmentConflictError
        assert reused.version == 3

        final = repo.get(a.id)
        assert final.status == AssessmentStatus.COMPLETED
        assert len(final.findings) == 1
        assert final.version == 3

    def test_single_chain_evolves_version_correctly(self, repo: LegacyAssessmentRepository) -> None:
        a = _new_authorized_assessment()
        repo.save(a)

        loaded = repo.get(a.id)
        loaded.start()
        repo.save(loaded)
        assert repo.get(a.id).version == 2

    def test_double_chain_evolves_version_correctly(self, repo: LegacyAssessmentRepository) -> None:
        a = _new_authorized_assessment()
        repo.save(a)

        first = repo.get(a.id)
        first.start()
        repo.save(first)

        second = repo.get(a.id)
        second.record_finding(_finding())
        second.complete()
        repo.save(second)

        final = repo.get(a.id)
        assert final.version == 3
        assert final.status == AssessmentStatus.COMPLETED
        assert len(final.findings) == 1

    def test_load_a_load_b_save_a_save_b_a_succeeds_b_fails(self, repo: LegacyAssessmentRepository) -> None:
        a0 = _new_authorized_assessment()
        repo.save(a0)

        writer_a = repo.get(a0.id)
        writer_b = repo.get(a0.id)
        writer_a.start()
        writer_b.start()

        repo.save(writer_a)  # succeeds: version 1 -> 2
        with pytest.raises(AssessmentConflictError):
            repo.save(writer_b)  # fails: still believes version 1

        final = repo.get(a0.id)
        assert final.version == 2
        assert final.status == AssessmentStatus.RUNNING

    def test_load_a_load_b_save_b_save_a_b_succeeds_a_fails(self, repo: LegacyAssessmentRepository) -> None:
        a0 = _new_authorized_assessment()
        repo.save(a0)

        writer_a = repo.get(a0.id)
        writer_b = repo.get(a0.id)
        writer_a.start()
        writer_b.start()

        repo.save(writer_b)  # succeeds: version 1 -> 2
        with pytest.raises(AssessmentConflictError):
            repo.save(writer_a)  # fails: still believes version 1

        final = repo.get(a0.id)
        assert final.version == 2
        assert final.status == AssessmentStatus.RUNNING


# ── Section 22: findings preservation ────────────────────────────────────


class TestFindingsPreservation:
    def test_multiple_real_findings_survive_a_rejected_stale_overwrite(self, repo: LegacyAssessmentRepository) -> None:
        a0 = _new_authorized_assessment()
        repo.save(a0)

        stale = repo.get(a0.id)  # findings=[], version=1
        assert len(stale.findings) == 0

        current = repo.get(a0.id)
        current.start()
        current.record_finding(_finding("SQLi"))
        current.record_finding(_finding("XSS"))
        current.record_finding(_finding("IDOR"))
        current.complete()
        repo.save(current)  # durable: 3 findings, COMPLETED, version 2

        with pytest.raises(AssessmentConflictError):
            stale.start()
            repo.save(stale)

        preserved = repo.get(a0.id)
        assert preserved.status == AssessmentStatus.COMPLETED
        assert {f.title for f in preserved.findings} == {"SQLi", "XSS", "IDOR"}
        assert preserved.version == 2

    def test_stale_nonempty_findings_cannot_overwrite_newer_findings(self, repo: LegacyAssessmentRepository) -> None:
        """A stale writer that itself recorded (different) findings before
        going stale must still never win - content richness on the losing
        side is irrelevant to the version check."""
        a0 = _new_authorized_assessment()
        repo.save(a0)

        stale = repo.get(a0.id)
        stale.start()
        stale.record_finding(_finding("StaleFinding"))
        # stale is NOT saved yet - still in-memory only, version=1.

        current = repo.get(a0.id)
        current.start()
        current.record_finding(_finding("RealFinding"))
        current.complete()
        repo.save(current)  # durable: version 2

        with pytest.raises(AssessmentConflictError):
            repo.save(stale)

        final = repo.get(a0.id)
        assert {f.title for f in final.findings} == {"RealFinding"}
        assert final.version == 2


# ── Section 21/23/24: terminal immutability across every terminal state ──


class TestTerminalImmutability:
    def test_completed_cannot_be_reverted_by_a_stale_running_writer(self, repo: LegacyAssessmentRepository) -> None:
        a0 = _new_authorized_assessment()
        repo.save(a0)
        stale = repo.get(a0.id)
        stale.start()

        current = repo.get(a0.id)
        current.start()
        current.complete()
        repo.save(current)

        with pytest.raises(AssessmentConflictError):
            repo.save(stale)
        assert repo.get(a0.id).status == AssessmentStatus.COMPLETED

    def test_failed_cannot_be_reverted_by_a_stale_running_writer(self, repo: LegacyAssessmentRepository) -> None:
        a0 = _new_authorized_assessment()
        repo.save(a0)
        stale = repo.get(a0.id)
        stale.start()

        current = repo.get(a0.id)
        current.start()
        current.fail("scanner unavailable")
        repo.save(current)

        with pytest.raises(AssessmentConflictError):
            repo.save(stale)
        final = repo.get(a0.id)
        assert final.status == AssessmentStatus.FAILED
        assert final.failure_reason == "scanner unavailable"

    def test_cancelled_cannot_be_reverted_by_a_stale_running_writer(self, repo: LegacyAssessmentRepository) -> None:
        a0 = _new_authorized_assessment()
        repo.save(a0)
        stale = repo.get(a0.id)
        stale.start()

        current = repo.get(a0.id)
        current.cancel()
        repo.save(current)

        with pytest.raises(AssessmentConflictError):
            repo.save(stale)
        assert repo.get(a0.id).status == AssessmentStatus.CANCELLED


# ── Section 25: version replay attack ────────────────────────────────────


class TestVersionReplayAttack:
    def test_reusing_an_old_version_after_several_advances_is_rejected(self, repo: LegacyAssessmentRepository) -> None:
        a0 = _new_authorized_assessment()
        repo.save(a0)  # version 1

        replay_copy = repo.get(a0.id)  # captures version 1

        v = repo.get(a0.id)
        v.start()
        repo.save(v)  # version 2
        v = repo.get(a0.id)
        v.record_finding(_finding())
        repo.save(v)  # version 3 (record_finding alone doesn't change status; still a real save)
        v = repo.get(a0.id)
        v.complete()
        repo.save(v)  # version 4

        assert repo.get(a0.id).version == 4

        # Attacker/stale caller submits a save carrying the OLD version=1
        # expectation, deliberately reusing a version far behind current.
        with pytest.raises(AssessmentConflictError):
            replay_copy.start()
            repo.save(replay_copy)

        final = repo.get(a0.id)
        assert final.version == 4
        assert final.status == AssessmentStatus.COMPLETED


# ── Section 26: version is never client-controlled ───────────────────────


class TestVersionNotClientControlled:
    def test_http_create_and_submit_bodies_have_no_version_field(self) -> None:
        """Documents (does not merely assume) that no client-controlled
        version field exists anywhere in the request schemas - confirmed
        by source re-read of CreateAssessmentRequest/SubmitAssessmentRequest
        (application/dto.py) and their HTTP body schemas
        (adapters/inbound/web/schemas.py), neither of which declares a
        version/expected_version field. Assessment.version is populated
        exclusively by the mapper from the real database row
        (assessment_to_domain()) or defaulted to 0 by the domain
        constructor - never from user input."""
        from kingsec.application.dto import CreateAssessmentRequest, SubmitAssessmentRequest

        assert "version" not in CreateAssessmentRequest.__dataclass_fields__
        assert "version" not in SubmitAssessmentRequest.__dataclass_fields__


# ── Section 30: persistence failure modes ────────────────────────────────


class TestPersistenceFailureModes:
    def test_stale_version_save_does_not_partially_write(self, repo: LegacyAssessmentRepository, session_factory) -> None:
        a0 = _new_authorized_assessment()
        repo.save(a0)
        stale = repo.get(a0.id)

        current = repo.get(a0.id)
        current.start()
        repo.save(current)

        with pytest.raises(AssessmentConflictError):
            stale.start()
            repo.save(stale)

        # Exactly one row still exists for this id - no orphaned/partial
        # duplicate row was left behind by the rejected attempt.
        with session_factory() as session:
            rows = session.execute(select(AssessmentORM).where(AssessmentORM.id == str(a0.id))).scalars().all()
            assert len(rows) == 1
            assert rows[0].status == "RUNNING"
            assert rows[0].version == 2

    def test_saving_a_stale_copy_of_a_since_deleted_assessment_raises_conflict_not_resurrect(
        self, repo: LegacyAssessmentRepository
    ) -> None:
        """Case B (missing Assessment): a stale caller's save() must never
        silently resurrect a genuinely deleted assessment with stale
        content - it must fail exactly like any other version mismatch."""
        a0 = _new_authorized_assessment()
        repo.save(a0)
        stale = repo.get(a0.id)  # version 1

        repo.delete(a0.id)

        with pytest.raises(AssessmentConflictError):
            stale.start()
            repo.save(stale)

        with pytest.raises(AssessmentNotFoundError):
            repo.get(a0.id)

    def test_fresh_insert_of_a_colliding_id_raises_conflict_not_integrity_error(
        self, repo: LegacyAssessmentRepository
    ) -> None:
        """version == 0 (never-persisted) callers get a plain insert - but
        if the id turns out to already exist, that must surface as
        AssessmentConflictError, not a raw sqlalchemy.exc.IntegrityError
        leaking past the repository boundary. A genuinely SEPARATE, freshly
        constructed object sharing the same id as an already-persisted row
        is used here (rather than re-saving the exact same object twice -
        after the KSEC-108-01 in-place version bump fix, persist_assessment()
        now correctly advances a reused object's own version on success,
        so re-saving the identical Python object a second time is a
        legitimate, successful update, not a collision - see
        TestLoadMutateSaveContract's dedicated test for that behavior)."""
        a0 = _new_authorized_assessment()
        repo.save(a0)

        colliding = Assessment(a0.id, a0.target)
        assert colliding.version == 0  # a genuinely fresh, never-fetched object

        with pytest.raises(AssessmentConflictError):
            repo.save(colliding)


# ── Section 13: 2/4/8-way multi-writer races at the raw repository level ─


class TestMultiWriterRaces:
    @pytest.mark.parametrize("n_writers", [2, 4, 8])
    def test_exactly_one_writer_wins_the_same_version_transition(
        self, repo: LegacyAssessmentRepository, session_factory, n_writers: int
    ) -> None:
        a0 = _new_authorized_assessment()
        repo.save(a0)  # version 1, AUTHORIZED

        barrier = threading.Barrier(n_writers)
        outcomes: list[str] = [""] * n_writers

        def _attempt(i: int) -> None:
            writer = repo.get(a0.id)  # every writer reads the SAME version 1
            barrier.wait(timeout=10)
            try:
                writer.start()
                repo.save(writer)
                outcomes[i] = "ok"
            except AssessmentConflictError:
                outcomes[i] = "conflict"

        threads = [threading.Thread(target=_attempt, args=(i,)) for i in range(n_writers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        assert outcomes.count("ok") == 1, f"expected exactly one winner, got outcomes={outcomes}"
        assert outcomes.count("conflict") == n_writers - 1

        final = repo.get(a0.id)
        assert final.status == AssessmentStatus.RUNNING
        assert final.version == 2

        with session_factory() as session:
            rows = session.execute(select(AssessmentORM).where(AssessmentORM.id == str(a0.id))).scalars().all()
            assert len(rows) == 1, "no duplicate Assessment rows were created by the race"
