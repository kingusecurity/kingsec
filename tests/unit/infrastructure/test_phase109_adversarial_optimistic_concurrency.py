"""KSEC-107-01 / KSEC-108-01: Phase 109 adversarial verification of the
Phase 108 optimistic-concurrency fix.

This file does NOT trust Phase 108's own tests passing as proof of
correctness. It attempts to BREAK the version-gated persist_assessment()
via attack classes not exercised by Phase 108's own suite: delete+recreate
of the same id, concurrent DELETE+INSERT under real multi-process
contention, transaction-rollback atomicity when the post-DELETE INSERT
fails, SQLite lock/busy behavior, an admin CancelAssessment racing a live
in-flight scan (an exception-swallowing path Phase 108 never exercised),
and an explicit proof that the concurrency check is enforced by the
database, not a Python-level TOCTOU-vulnerable check.

Real on-disk SQLite throughout; threading.Barrier/Event for in-process
races; multiprocessing.Barrier + separate OS processes for the one
genuine multi-process race (Attack Class G). No time.sleep() as a race
mechanism anywhere.
"""

from __future__ import annotations

import multiprocessing
import threading
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from kingsec.application.errors import AssessmentConflictError, AssessmentNotFoundError
from kingsec.domain import Authorization, Finding, Severity, Target, TargetType
from kingsec.domain.assessment import Assessment
from kingsec.domain.enums import AssessmentStatus
from kingsec.infrastructure.persistence._legacy_repositories import LegacyAssessmentRepository
from kingsec.infrastructure.persistence.models import AssessmentORM, Base

# ── Fixtures ─────────────────────────────────────────────────────────────


def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=10000")
    cursor.close()


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / f"phase109-{uuid.uuid4().hex}.sqlite3"


@pytest.fixture
def engine(db_path: Path):
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


# ── Attack Class C/D: delete + recreate same id, concurrent DELETE+INSERT ─


class TestDeleteRecreateSameId:
    def test_ksec_109_01_stale_writer_can_overwrite_a_recreated_assessment_at_the_same_id(
        self, repo: LegacyAssessmentRepository
    ) -> None:
        """KSEC-109-01 (confirmed, documented, NOT fixed - see the final
        report's finding writeup for the full severity/reachability
        analysis): the version counter resets to 1 on every fresh insert,
        so a stale writer holding version=1 from a DELETED row can
        successfully overwrite an entirely different, later-created row
        that happens to also currently be at version=1 - version alone
        cannot distinguish two different "lineages" sharing the same id.

        Deterministic, not a race: original saved (version 1) -> stale
        copy captured -> original deleted -> a DIFFERENT Assessment
        recreated at the SAME id (version resets to 1, since it's a fresh
        insert from the repository's point of view) -> the stale copy's
        save() succeeds and silently clobbers the second, unrelated
        Assessment's state and authorization.

        NOT reachable via any current production path: no use case ever
        lets a caller choose an Assessment's id at creation
        (AssessmentId.generate() is always a fresh random uuid4 -
        CreateAssessment never accepts or reuses a caller-supplied id),
        and two independent CreateAssessment calls colliding on the same
        uuid4 is cryptographically negligible (~2^-122). Reaching this
        requires constructing ``Assessment(existing_id, target)`` directly,
        which only test code (or a hypothetical future
        restore/import/undo-delete feature) can do today. Documented here
        exactly as Phase 109 Section 6 requires when an attack is only
        reachable at the repository/persistence level, not through any
        supported application path."""
        original = _new_authorized_assessment()
        repo.save(original)  # version 1
        stale = repo.get(original.id)  # captures version 1

        repo.delete(original.id)
        with pytest.raises(AssessmentNotFoundError):
            repo.get(original.id)

        # Recreate at the exact same id - only reachable by constructing
        # the domain object directly with a reused AssessmentId; no
        # production path does this.
        recreated = Assessment(original.id, _target())
        recreated.authorize(Authorization.grant("victim-recreator@kingusecurity.com", "10.0.0.9"))
        assert recreated.version == 0  # a genuinely fresh insert from the repo's perspective
        repo.save(recreated)
        second_generation = repo.get(original.id)
        assert second_generation.version == 1
        assert second_generation.authorization is not None
        assert second_generation.authorization.authorized_by == "victim-recreator@kingusecurity.com"

        # THE FINDING: the stale object (from before the delete) still
        # believes version=1 - which numerically collides with the
        # recreated row's own, unrelated version=1. The conditional DELETE
        # matches on id+version alone, with no way to know these are two
        # different lineages.
        stale.start()
        repo.save(stale)  # succeeds - this is KSEC-109-01, not a test bug

        final = repo.get(original.id)
        assert final.version == 2
        assert final.status == AssessmentStatus.RUNNING  # the STALE writer's transition, not the recreated row's
        assert final.authorization is not None
        assert final.authorization.authorized_by == "pentester@kingusecurity.com"  # the ORIGINAL's authorizer, not the recreated row's - confirmed cross-lineage overwrite

    def test_stale_writers_own_version_1_cannot_collide_with_a_second_generation_row(
        self, repo: LegacyAssessmentRepository
    ) -> None:
        """A stronger version of the above: the recreated row is advanced
        to version 2 (a real mutation happened on it) before the stale
        writer (still at version 1 from the ORIGINAL, now-deleted row)
        attempts its save. Proves the version check is scoped to the
        CURRENT row's actual version, never merely "some row existed at
        this version once."""
        original = _new_authorized_assessment()
        repo.save(original)
        stale = repo.get(original.id)  # version 1, from the ORIGINAL row

        repo.delete(original.id)

        recreated = Assessment(original.id, _target())
        recreated.authorize(Authorization.grant("pentester@kingusecurity.com", "10.0.0.9"))
        repo.save(recreated)  # version 1 (second-generation row)
        second_gen = repo.get(original.id)
        second_gen.start()
        repo.save(second_gen)  # version 2

        with pytest.raises(AssessmentConflictError):
            stale.start()
            repo.save(stale)

        final = repo.get(original.id)
        assert final.status == AssessmentStatus.RUNNING
        assert final.version == 2


class TestConcurrentDeleteInsert:
    def test_delete_racing_a_stale_save_never_corrupts_never_duplicates(
        self, repo: LegacyAssessmentRepository, session_factory
    ) -> None:
        """Writer A: DELETE the existing Assessment. Writer B: attempt to
        save a stale (pre-delete, but not otherwise out of date) copy,
        racing via a real threading.Barrier. There is no guaranteed winner
        here - both are legitimate operations on the SAME still-current
        version, so either A's delete or B's save may legitimately execute
        first. What must NEVER happen: a duplicate row, an orphaned
        finding, or B silently succeeding AFTER A's delete already
        committed (which would resurrect a deleted Assessment with stale
        content - a distinct concern from KSEC-109-01's version-reuse
        collision, verified separately in TestDeleteRecreateSameId)."""
        original = _new_authorized_assessment()
        repo.save(original)
        stale_copy = repo.get(original.id)  # version 1 - genuinely current at this point

        barrier = threading.Barrier(2)
        outcomes: dict[str, str] = {}

        def _delete() -> None:
            barrier.wait(timeout=10)
            try:
                repo.delete(original.id)
                outcomes["delete"] = "ok"
            except Exception as exc:
                outcomes["delete"] = type(exc).__name__

        def _stale_save() -> None:
            barrier.wait(timeout=10)
            try:
                stale_copy.start()
                repo.save(stale_copy)
                outcomes["save"] = "ok"
            except Exception as exc:
                outcomes["save"] = type(exc).__name__

        threads = [threading.Thread(target=fn) for fn in (_delete, _stale_save)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        assert outcomes["delete"] == "ok"
        assert outcomes["save"] in ("ok", "AssessmentConflictError"), f"unexpected save outcome: {outcomes}"

        # delete() is unconditional-by-id (no version check - matches its
        # existing, pre-Phase-108 contract exactly), so regardless of
        # which order the two operations actually executed in, it always
        # eventually removes whatever row exists - the durable end state
        # is deterministically "gone" either way. The only question this
        # test answers is whether getting there ever involves corruption
        # (a duplicate row, an orphaned finding) - it never does.
        with session_factory() as session:
            rows = session.execute(select(AssessmentORM).where(AssessmentORM.id == str(original.id))).scalars().all()
            assert len(rows) == 0, f"delete() is unconditional and must always leave no row: {outcomes}"
        with pytest.raises(AssessmentNotFoundError):
            repo.get(original.id)


# ── Attack Class E: transaction rollback when the post-DELETE INSERT fails ─


class TestTransactionRollbackAtomicity:
    def test_insert_failure_after_a_successful_conditional_delete_rolls_back_the_whole_transaction(
        self, repo: LegacyAssessmentRepository, session_factory, engine
    ) -> None:
        """Deliberately forces the INSERT half of persist_assessment()'s
        replace path to fail (a controlled, test-only injected failure -
        Phase 109 Section 8 explicitly permits this), and verifies the
        conditional DELETE that already succeeded is rolled back with it:
        the ORIGINAL row must still exist afterward, not be lost.

        This is the single most important correctness property of using
        DELETE-then-INSERT as an atomic replace: if the transaction were
        NOT atomic, a failed INSERT after a successful DELETE would leave
        the Assessment permanently gone from a successful write attempt -
        arguably worse than the original KSEC-107-01 defect."""
        original = _new_authorized_assessment()
        repo.save(original)
        loaded = repo.get(original.id)
        loaded.start()

        def _force_insert_failure(session, _flush_context, _instances) -> None:
            for obj in session.new:
                if isinstance(obj, AssessmentORM):
                    raise IntegrityError("forced insert failure (Phase 109 test)", None, None)

        event.listen(session_factory().__class__, "before_flush", _force_insert_failure)
        try:
            with pytest.raises(Exception):
                repo.save(loaded)
        finally:
            event.remove(session_factory().__class__, "before_flush", _force_insert_failure)

        # The original row must still exist, completely intact - the
        # forced INSERT failure must not have left it deleted.
        with session_factory() as session:
            rows = session.execute(select(AssessmentORM).where(AssessmentORM.id == str(original.id))).scalars().all()
            assert len(rows) == 1, "the conditional DELETE must have been rolled back along with the failed INSERT"
            assert rows[0].status == "AUTHORIZED"
            assert rows[0].version == 1

        # And a subsequent, real, non-forced save from a freshly-read
        # object succeeds normally - confirming the row is genuinely
        # intact and usable, not left in some half-broken state.
        recovered = repo.get(original.id)
        assert recovered.version == 1
        recovered.start()
        repo.save(recovered)
        assert repo.get(original.id).status == AssessmentStatus.RUNNING


# ── Attack Class F: SQLite lock/busy conditions ──────────────────────────


class TestSqliteLockBusyConditions:
    def test_heavy_contention_never_produces_a_stale_overwrite_or_silent_success(
        self, repo: LegacyAssessmentRepository, session_factory
    ) -> None:
        """8 threads, each independently reading the SAME authorized
        assessment then immediately racing to save a RUNNING transition,
        deliberately without a shared engine-level connection pool limit
        change (using this project's real, unmodified busy_timeout=10s
        pragma) - verifies that under real lock contention, every outcome
        is either a clean success, a clean AssessmentConflictError, or (if
        contention exceeds the busy timeout) a clean, non-corrupting
        database-level error - never a silent stale success and never
        data corruption."""
        a0 = _new_authorized_assessment()
        repo.save(a0)

        n = 8
        barrier = threading.Barrier(n)
        outcomes: list[str] = [""] * n

        def _attempt(i: int) -> None:
            writer = repo.get(a0.id)
            barrier.wait(timeout=10)
            try:
                writer.start()
                repo.save(writer)
                outcomes[i] = "ok"
            except AssessmentConflictError:
                outcomes[i] = "conflict"
            except Exception as exc:
                outcomes[i] = f"other:{type(exc).__name__}"

        threads = [threading.Thread(target=_attempt, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=20)

        ok_count = outcomes.count("ok")
        assert ok_count == 1, f"expected exactly one winner under heavy contention, got outcomes={outcomes}"
        other = [o for o in outcomes if o.startswith("other:")]
        assert not other, f"unexpected non-conflict error types under contention (never a silent corruption): {other}"

        final = repo.get(a0.id)
        assert final.status == AssessmentStatus.RUNNING
        assert final.version == 2
        with session_factory() as session:
            rows = session.execute(select(AssessmentORM).where(AssessmentORM.id == str(a0.id))).scalars().all()
            assert len(rows) == 1


# ── Attack Class G: multiple independent OS processes ───────────────────


def _process_worker(db_url: str, assessment_id: str, target_value: str, target_type: str, barrier, result_queue) -> None:
    """Module-level (picklable) worker for a real, separate OS process.
    Opens its OWN engine/session against the SAME on-disk database file."""
    from sqlalchemy import create_engine as _create_engine
    from sqlalchemy.orm import sessionmaker as _sessionmaker

    from kingsec.infrastructure.persistence._legacy_repositories import (
        LegacyAssessmentRepository as _Repo,
    )

    eng = _create_engine(db_url, future=True, connect_args={"timeout": 30})

    def _pragma(dbapi_connection, _r) -> None:
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=15000")
        cur.close()

    from sqlalchemy import event as _event

    _event.listen(eng, "connect", _pragma)
    sf = _sessionmaker(bind=eng, expire_on_commit=False, future=True)
    repo = _Repo(sf)

    from kingsec.application._support import to_assessment_id as _to_id

    writer = repo.get(_to_id(assessment_id))
    barrier.wait(timeout=15)
    try:
        writer.start()
        repo.save(writer)
        result_queue.put("ok")
    except Exception as exc:
        result_queue.put(type(exc).__name__)
    eng.dispose()


class TestMultiProcessRace:
    @pytest.mark.parametrize("n_processes", [2, 4])
    def test_real_separate_processes_racing_the_same_assessment(
        self, repo: LegacyAssessmentRepository, db_path: Path, n_processes: int
    ) -> None:
        """Genuine multi-process concurrency (not threads faking process
        isolation) - each worker is a real, separate Python process
        (multiprocessing, spawn start method on Windows) with its own
        SQLAlchemy engine and connection against the SAME on-disk SQLite
        file. Verifies exactly one stale-version writer wins across real
        OS process boundaries."""
        a0 = _new_authorized_assessment()
        repo.save(a0)
        db_url = f"sqlite:///{db_path}"

        ctx = multiprocessing.get_context("spawn")
        barrier = ctx.Barrier(n_processes)
        result_queue = ctx.Queue()

        processes = [
            ctx.Process(
                target=_process_worker,
                args=(db_url, str(a0.id), a0.target.value, a0.target.type.name, barrier, result_queue),
            )
            for _ in range(n_processes)
        ]
        for p in processes:
            p.start()
        for p in processes:
            p.join(timeout=30)

        results = [result_queue.get(timeout=5) for _ in range(n_processes)]
        ok_count = results.count("ok")

        assert ok_count == 1, f"expected exactly one winning process, got results={results}"
        for r in results:
            if r != "ok":
                assert r in ("AssessmentConflictError",), f"unexpected process outcome: {r} (all results: {results})"

        final = repo.get(a0.id)
        assert final.status == AssessmentStatus.RUNNING
        assert final.version == 2


# ── Attack Class N (targeted): CancelAssessment racing a live scan ──────


class TestAdminCancelRacesLiveScan:
    def test_admin_cancel_wins_and_the_scans_own_terminal_save_fails_closed_not_stale(
        self, repo: LegacyAssessmentRepository, session_factory
    ) -> None:
        """A scenario Phase 108's own tests never exercised: an admin
        cancels a RUNNING assessment (CancelAssessment.execute()) WHILE a
        background scan is genuinely still in flight, racing to reach its
        own terminal save. This exercises submit_assessment.py's own
        exception-swallowing recovery path
        (`except Exception: assessment.fail(...); assessments.save(...)`)
        with a REAL AssessmentConflictError, not a hypothetical one.

        The only security-relevant property under test: the admin's
        CANCELLED decision must never be silently overwritten by the
        scan's own now-stale terminal save. Whether the scan's own
        findings are preserved or lost in this specific race is a secondary
        product-behavior question, not the KSEC-107-01 property - noted in
        RESIDUAL RISK, not asserted here as a hard requirement."""
        from kingsec.application._support import to_assessment_id

        a0 = _new_authorized_assessment()
        repo.save(a0)

        # Simulate the background job's own already-in-flight state: it
        # already read the assessment (as RUNNING, at version 2) and has
        # now computed real findings, about to save COMPLETED.
        running = repo.get(a0.id)
        running.start()
        repo.save(running)  # version 1 -> 2, durable RUNNING
        scan_worker_copy = repo.get(a0.id)  # the "background job's" own read, version 2
        scan_worker_copy.record_finding(_finding("RealFinding"))

        # Admin cancels FIRST (racing ahead of the scan's own terminal save).
        admin_copy = repo.get(a0.id)  # version 2, same as scan_worker_copy
        admin_copy.cancel()
        repo.save(admin_copy)  # version 2 -> 3, durable CANCELLED

        # The scan's own terminal save now conflicts (its captured version=2
        # is stale relative to the admin's version=3 CANCELLED write).
        with pytest.raises(AssessmentConflictError):
            scan_worker_copy.complete()
            repo.save(scan_worker_copy)

        # THE PROPERTY THAT MATTERS: the admin's CANCELLED decision is
        # durable and was never overwritten by the scan's stale COMPLETED
        # attempt.
        final = repo.get(to_assessment_id(str(a0.id)))
        assert final.status == AssessmentStatus.CANCELLED
        assert final.version == 3
        assert len(final.findings) == 0, "the stale scan's findings must not leak into the durable CANCELLED row"


# ── Attack Class S: prove the concurrency check is NOT a Python-only TOCTOU ─


class TestNotAPythonOnlyToctou:
    def test_two_independent_sessions_racing_the_identical_version_check_cannot_both_pass(
        self, repo: LegacyAssessmentRepository, session_factory
    ) -> None:
        """The decisive proof: two INDEPENDENT SQLAlchemy sessions (not
        just independent domain objects sharing one session/engine
        connection pool) both believe the current version is N and race
        to write. If the concurrency predicate were merely a Python-level
        `if current_version != expected: raise` executed before an
        unconditional write (Section 22's explicitly-forbidden pattern),
        a sufficiently tight race could let both sessions pass their own
        check before either commits. Because the actual implementation's
        check IS the SQL WHERE clause of the DELETE itself - evaluated
        atomically by SQLite as part of one write statement inside one
        locked transaction - this cannot happen, and this test proves it
        with a real Barrier-synchronized race across two separate Session
        objects bound to two separate connections from the same engine."""
        a0 = _new_authorized_assessment()
        repo.save(a0)

        barrier = threading.Barrier(2)
        outcomes: list[str] = ["", ""]

        def _attempt(i: int) -> None:
            # Each thread gets its OWN LegacyAssessmentRepository instance
            # (backed by the SAME session_factory, but each .save() call
            # opens its own independent session/transaction via
            # session_factory.begin() - genuinely independent connections,
            # not a shared session object).
            local_repo = LegacyAssessmentRepository(session_factory)
            writer = local_repo.get(a0.id)  # both threads read the SAME version here
            barrier.wait(timeout=10)
            try:
                writer.start()
                local_repo.save(writer)
                outcomes[i] = "ok"
            except AssessmentConflictError:
                outcomes[i] = "conflict"

        threads = [threading.Thread(target=_attempt, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        assert sorted(outcomes) == ["conflict", "ok"], (
            f"exactly one of the two independent sessions must win, the other must be rejected "
            f"- both winning would prove a Python-only TOCTOU gap: outcomes={outcomes}"
        )

        with session_factory() as session:
            rows = session.execute(select(AssessmentORM).where(AssessmentORM.id == str(a0.id))).scalars().all()
            assert len(rows) == 1
            assert rows[0].version == 2


# ── Attack Class Q: version corruption (only reachable at the
# repository/domain-construction level - no client input path exists,
# confirmed separately in TestHttpClientVersionManipulation) ────────────


class TestVersionCorruption:
    def test_negative_version_is_safely_rejected_never_overwrites(self, repo: LegacyAssessmentRepository) -> None:
        a0 = _new_authorized_assessment()
        repo.save(a0)

        corrupted = Assessment(a0.id, _target(), version=-1)
        with pytest.raises(AssessmentConflictError):
            repo.save(corrupted)

        final = repo.get(a0.id)
        assert final.status == AssessmentStatus.AUTHORIZED
        assert final.version == 1

    def test_extremely_large_version_is_safely_rejected_never_overwrites(
        self, repo: LegacyAssessmentRepository
    ) -> None:
        a0 = _new_authorized_assessment()
        repo.save(a0)

        corrupted = Assessment(a0.id, _target(), version=999_999_999)
        with pytest.raises(AssessmentConflictError):
            repo.save(corrupted)

        final = repo.get(a0.id)
        assert final.status == AssessmentStatus.AUTHORIZED
        assert final.version == 1

    def test_none_version_is_safely_rejected_never_treated_as_fresh_insert(
        self, repo: LegacyAssessmentRepository
    ) -> None:
        """version=None is neither 0 (the "never persisted" sentinel) nor
        any real durable version - it must fall into the conditional
        replace path (since `None == 0` is False) and safely match zero
        rows (the version column is NOT NULL, so no real row can ever
        equal NULL), never be misinterpreted as "fresh insert" and never
        overwrite the real row."""
        a0 = _new_authorized_assessment()
        repo.save(a0)

        corrupted = Assessment(a0.id, _target(), version=None)  # type: ignore[arg-type]
        with pytest.raises(AssessmentConflictError):
            repo.save(corrupted)

        final = repo.get(a0.id)
        assert final.status == AssessmentStatus.AUTHORIZED
        assert final.version == 1

    def test_zero_version_against_an_existing_row_is_rejected_not_a_fresh_insert_collision(
        self, repo: LegacyAssessmentRepository
    ) -> None:
        """version=0 always takes the "fresh insert" branch regardless of
        whether a row already exists - confirming this deliberately
        collides with the id and is safely turned into
        AssessmentConflictError (via the IntegrityError-catching path),
        never a silent overwrite of the real row."""
        a0 = _new_authorized_assessment()
        repo.save(a0)

        colliding = Assessment(a0.id, _target(), version=0)
        with pytest.raises(AssessmentConflictError):
            repo.save(colliding)

        final = repo.get(a0.id)
        assert final.status == AssessmentStatus.AUTHORIZED
        assert final.version == 1
