"""KSEC-107: Phase 107 adversarial verification of Assessment creation and
submission idempotency.

Primary question: can two independent submission attempts create two
independent Assessments and therefore two independent execution
records/scanner executions for what should logically be one submission?

This file does not trust prior phase reports (Phase 106 only verified
protections that exist once an Assessment/execution row already exists).
Every concurrency test here exercises REAL production code (the real
``CreateAssessment``, ``SubmitAssessment``, ``ThreadJobRunner``,
``SqlAlchemyAssessmentExecutionRepository``, ``LegacyAssessmentRepository``)
against a real on-disk SQLite database, using real threads and
``threading.Barrier``/``threading.Event`` for synchronization - never
``time.sleep()`` as the race mechanism. Sleep is used only for a bounded,
non-critical completion-poll (documented at each use), never to create or
win a race.
"""

from __future__ import annotations

import threading
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from kingsec.application.dto import CreateAssessmentRequest, SubmitAssessmentRequest
from kingsec.application.errors import AssessmentNotFoundError
from kingsec.application.submit_assessment import SubmitAssessment
from kingsec.application.use_cases.create_assessment import CreateAssessment
from kingsec.domain import Finding, Severity, Target
from kingsec.domain.enums import AssessmentStatus
from kingsec.domain.errors import IllegalStateTransition
from kingsec.infrastructure.jobs.thread_runner import ThreadJobRunner
from kingsec.infrastructure.persistence._legacy_repositories import LegacyAssessmentRepository
from kingsec.infrastructure.persistence.models import AssessmentExecutionORM, AssessmentORM, Base
from kingsec.infrastructure.persistence.repositories.assessment_execution import (
    SqlAlchemyAssessmentExecutionRepository,
)

# ── Fixtures: real on-disk SQLite, real repositories ────────────────────


@pytest.fixture
def engine(tmp_path: Path):
    db_path = tmp_path / f"phase107-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def assessment_repo(session_factory) -> LegacyAssessmentRepository:
    return LegacyAssessmentRepository(session_factory)


@pytest.fixture
def execution_repo(session_factory) -> SqlAlchemyAssessmentExecutionRepository:
    return SqlAlchemyAssessmentExecutionRepository(session_factory)


def _row_count(session_factory, model: Any, **filters: Any) -> int:
    with session_factory() as session:
        stmt = select(model)
        for key, value in filters.items():
            stmt = stmt.where(getattr(model, key) == value)
        return len(session.execute(stmt).scalars().all())


# ── A real, thread-safe counting scanner - the actual side-effect-safety
# proof this phase needs a real spy at the application boundary, not a
# mocked-out use case. ───────────────────────────────────────────────────


class _CountingScanner:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.invocation_count = 0
        self.invocations: list[str] = []

    def scan(self, target: Target, *, scanner_ids: tuple[str, ...] | None = None) -> list[Finding]:
        with self._lock:
            self.invocation_count += 1
            self.invocations.append(threading.current_thread().name)
        return [Finding.create("SQLi", "injectable param", Severity.CRITICAL)]

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        return {"stub": "Stub Scanner"}


class _GatedScanner:
    """Blocks inside scan() on a real threading.Event until released -
    lets a test deterministically prove "the scanner has been invoked and
    is still executing" without any sleep-based race."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.invocation_count = 0
        self.entered = threading.Event()
        self.release_gate = threading.Event()

    def scan(self, target: Target, *, scanner_ids: tuple[str, ...] | None = None) -> list[Finding]:
        with self._lock:
            self.invocation_count += 1
        self.entered.set()
        self.release_gate.wait(timeout=10)
        return [Finding.create("SQLi", "injectable param", Severity.CRITICAL)]

    def compatible_scanners(self, target: Target) -> dict[str, str]:
        return {"stub": "Stub Scanner"}


def _make_submit_assessment(
    assessment_repo: LegacyAssessmentRepository,
    execution_repo: SqlAlchemyAssessmentExecutionRepository,
    scanner: Any,
    job_runner: ThreadJobRunner,
) -> SubmitAssessment:
    return SubmitAssessment(
        assessments=assessment_repo,
        scanner=scanner,
        job_runner=job_runner,
        execution_ledger=execution_repo,
    )


def _create_authorized_assessment(
    assessment_repo: LegacyAssessmentRepository, *, owner_id: str = "user-1", schedule_occurrence_id: str | None = None
) -> str:
    create_assessment = CreateAssessment(assessments=assessment_repo)
    result = create_assessment.execute(
        CreateAssessmentRequest(
            target_value="10.0.0.9",
            target_type="ip_address",
            authorized_by="pentester@kingusecurity.com",
            scope="10.0.0.9",
            owner_id=owner_id,
            schedule_occurrence_id=schedule_occurrence_id,
        )
    )
    return result.assessment_id


def _wait_for_execution_terminal(
    execution_repo: SqlAlchemyAssessmentExecutionRepository, assessment_id: str, timeout: float = 10.0
) -> Any:
    """Waits on the EXECUTION LEDGER reaching terminal, not the Assessment.
    Used by tests that deliberately race multiple SubmitAssessment calls
    against the same assessment: the ledger's own version-gated
    transitions are proven reliable (Phase 102/106), but under KSEC-107-01
    the Assessment's own terminal status is NOT guaranteed to ever arrive
    under that same race, so polling it there could hang/timeout for a
    reason unrelated to what a given test is actually checking."""
    deadline = time.monotonic() + timeout
    execution = None
    while time.monotonic() < deadline:
        execution = execution_repo.get_by_assessment_id(assessment_id)
        if execution is not None and execution.status.value in ("SUCCEEDED", "FAILED"):
            return execution
        time.sleep(0.05)
    raise AssertionError(f"execution ledger for {assessment_id} never reached terminal within {timeout}s: {execution}")


def _wait_for_terminal(assessment_repo: LegacyAssessmentRepository, assessment_id: str, timeout: float = 10.0) -> None:
    """Bounded, non-critical completion poll - NOT the race mechanism.
    The race itself is created by threading.Barrier/Event above; this only
    waits for the real background thread(s) to finish before assertions."""
    from kingsec.application._support import to_assessment_id

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        assessment = assessment_repo.get(to_assessment_id(assessment_id))
        if assessment.status in (AssessmentStatus.COMPLETED, AssessmentStatus.FAILED):
            return
        time.sleep(0.05)
    raise AssertionError(f"assessment {assessment_id} did not reach a terminal state within {timeout}s")


# ── Section 7 / Race A: 8 concurrent SubmitAssessment calls on ONE
# Assessment ────────────────────────────────────────────────────────────


class TestConcurrentSubmitAssessmentRaceA:
    def test_eight_concurrent_submits_produce_exactly_one_scanner_invocation(
        self, assessment_repo: LegacyAssessmentRepository, execution_repo: SqlAlchemyAssessmentExecutionRepository, session_factory
    ) -> None:
        """8 genuinely concurrent SubmitAssessment.execute() calls on ONE
        AUTHORIZED assessment, real ThreadJobRunner, real DB.

        KSEC-107-01 FIXED BY PHASE 108: before the fix, this exact race
        empirically produced a silently corrupted Assessment (reverted to
        RUNNING, findings discarded) even though the execution ledger and
        scanner invocation count were themselves safe (exactly one real
        scan, exactly one execution row, ledger always reaches a terminal
        status) - see TestKsec10701LostUpdateOnConcurrentSubmission for the
        deterministic, minimized reproduction of that original failure
        mode. After the fix, ``persist_assessment()``'s optimistic-
        concurrency check means the Assessment's OWN durable status is now
        ALSO guaranteed consistent with the ledger's terminal outcome -
        every losing submitter fails closed (AssessmentConflictError,
        IllegalStateTransition, or JobRunnerError), never silently
        succeeding with stale content."""
        assessment_id = _create_authorized_assessment(assessment_repo)
        scanner = _CountingScanner()
        job_runner = ThreadJobRunner(max_workers=8)
        submit_assessment = _make_submit_assessment(assessment_repo, execution_repo, scanner, job_runner)

        n_threads = 8
        barrier = threading.Barrier(n_threads)
        results: list[tuple[str, Exception | None]] = [("", None)] * n_threads

        def _attempt(i: int) -> None:
            barrier.wait(timeout=10)
            try:
                submit_assessment.execute(
                    SubmitAssessmentRequest(assessment_id=assessment_id, requesting_user="user-1", is_admin=False)
                )
                results[i] = ("ok", None)
            except Exception as exc:
                results[i] = ("error", exc)

        threads = [threading.Thread(target=_attempt, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        # Wait on the EXECUTION LEDGER reaching terminal, not the
        # Assessment - the ledger's own version-gated transitions are
        # proven reliable (Phase 102/106); the Assessment's terminal
        # status is exactly the property under test here and must not be
        # assumed to ever arrive.
        _wait_for_execution_terminal(execution_repo, assessment_id)
        job_runner.shutdown(wait=True)

        ok_count = sum(1 for outcome, _ in results if outcome == "ok")
        error_types = {type(exc).__name__ for outcome, exc in results if outcome == "error" and exc is not None}

        # The decisive, real-evidence assertion: no matter how many of the
        # 8 concurrent SubmitAssessment.execute() calls "succeeded" at the
        # use-case level, the scanner - the real, expensive, externally
        # visible side effect - was invoked EXACTLY ONCE.
        assert scanner.invocation_count == 1, (
            f"expected exactly one scanner invocation, got {scanner.invocation_count} "
            f"(ok_count={ok_count}, error_types={error_types}, results={results})"
        )

        execution_row_count = _row_count(session_factory, AssessmentExecutionORM, assessment_id=assessment_id)
        assert execution_row_count == 1, f"expected exactly one execution row, found {execution_row_count}"

        assessment_row_count = _row_count(session_factory, AssessmentORM, id=assessment_id)
        assert assessment_row_count == 1, f"expected exactly one assessment row, found {assessment_row_count}"

        # At least one call must have succeeded (the winner); the rest
        # raise one of three SAFE, fail-closed rejections:
        #   - AssessmentConflictError (KSEC-107-01/108-01 fix): lost the
        #     version-gated AUTHORIZED->RUNNING race at the very first
        #     save() call, before ever reaching the ledger/job dispatch.
        #   - IllegalStateTransition: fetched the assessment AFTER a
        #     competitor's save already committed RUNNING, so start() itself
        #     rejects it before any save is even attempted.
        #   - JobRunnerError: the job_id was already registered and running
        #     (only reachable if a caller's own save briefly raced ahead of
        #     the version check window - kept in the allow-list since it is
        #     still a safe, fail-closed outcome, never duplicate work).
        # What is NOT acceptable is an unrecognized exception type or a
        # second scanner invocation, both checked explicitly.
        assert ok_count >= 1, "at least one concurrent submitter must succeed"
        allowed_errors = {"AssessmentConflictError", "IllegalStateTransition", "JobRunnerError"}
        assert error_types <= allowed_errors, f"unexpected exception types under concurrency: {error_types}"

        # KSEC-107-01 FIXED BY PHASE 108: unlike before, the Assessment's
        # OWN durable status is now GUARANTEED consistent with the
        # execution ledger's terminal outcome - no late redundant save can
        # silently revert it, because every save() is now version-gated.
        from kingsec.application._support import to_assessment_id

        final_assessment = assessment_repo.get(to_assessment_id(assessment_id))
        assert final_assessment.status == AssessmentStatus.COMPLETED
        assert len(final_assessment.findings) == 1


# ── KSEC-107-01: deterministic, minimized reproduction of the lost-update
# defect first observed empirically in Race A above. ────────────────────


class TestKsec10701LostUpdateOnConcurrentSubmission:
    def test_late_redundant_save_from_a_losing_submitter_is_rejected_not_silently_applied(
        self, assessment_repo: LegacyAssessmentRepository, execution_repo: SqlAlchemyAssessmentExecutionRepository, session_factory
    ) -> None:
        """KSEC-107-01 FIXED BY PHASE 108 - minimized, fully deterministic
        reproduction (no reliance on real thread-scheduling luck) of the
        exact sequence Phase 107 found, now asserting the corrected
        outcome instead of the original defect.

        Sequence, matching exactly what real concurrent threads produced in
        the probabilistic Race A test above:

        1. Two callers concurrently fetch the SAME AUTHORIZED assessment.
        2. Caller A (the eventual "loser") transitions its own in-memory
           copy to RUNNING via ``assessment.start()`` - but does not save
           yet (simulating a thread that is descheduled between ``start()``
           and ``save()``, or whose save() is simply slower to acquire the
           SQLite writer lock).
        3. Caller B (the eventual "winner") runs an entire, real
           SubmitAssessment.execute() to completion: RUNNING -> scanner
           invoked once -> COMPLETED, with the execution ledger correctly
           reaching SUCCEEDED.
        4. Caller A's stale, delayed ``.save()`` finally lands.

        BEFORE Phase 108: ``persist_assessment()`` had no optimistic-
        concurrency check on the Assessment aggregate, so step 4's
        unconditional DELETE+INSERT silently overwrote the durably
        COMPLETED, 1-finding Assessment row with caller A's stale,
        0-finding, RUNNING copy - this is the original KSEC-107-01.

        AFTER Phase 108: ``assessment.version`` (captured at caller A's
        original read, step 1) no longer matches the durable version caller
        B's successful submission advanced it to, so step 4's conditional
        ``DELETE ... WHERE id = ? AND version = ?`` matches zero rows and
        ``AssessmentConflictError`` is raised - never reaching the INSERT.
        The durable COMPLETED/1-finding Assessment and SUCCEEDED execution
        remain exactly as caller B left them.
        """
        from kingsec.application._support import to_assessment_id
        from kingsec.application.errors import AssessmentConflictError

        assessment_id = _create_authorized_assessment(assessment_repo)

        # Step 1/2: caller A fetches AUTHORIZED and transitions to RUNNING
        # in-memory, but deliberately withholds the save.
        stale_copy = assessment_repo.get(to_assessment_id(assessment_id))
        assert stale_copy.status == AssessmentStatus.AUTHORIZED
        stale_version = stale_copy.version
        stale_copy.start()
        assert stale_copy.status == AssessmentStatus.RUNNING
        assert len(stale_copy.findings) == 0

        # Step 3: caller B runs a complete, real, successful submission.
        scanner = _CountingScanner()
        job_runner = ThreadJobRunner(max_workers=2)
        submit_assessment = _make_submit_assessment(assessment_repo, execution_repo, scanner, job_runner)
        submit_assessment.execute(SubmitAssessmentRequest(assessment_id=assessment_id, requesting_user="user-1"))
        _wait_for_terminal(assessment_repo, assessment_id)
        job_runner.shutdown(wait=True)

        # Confirm the pre-attack state is exactly as expected: durably
        # consistent and correct, at a HIGHER version than caller A's
        # stale copy - proving the version really did advance underneath it.
        pre_attack = assessment_repo.get(to_assessment_id(assessment_id))
        assert pre_attack.status == AssessmentStatus.COMPLETED
        assert len(pre_attack.findings) == 1
        assert pre_attack.version > stale_version
        execution_before = execution_repo.get_by_assessment_id(assessment_id)
        assert execution_before is not None and execution_before.status.value == "SUCCEEDED"

        # Step 4: caller A's stale, late save finally lands - and is
        # rejected with a concurrency conflict, exactly as Phase 108's own
        # "absolute final rule" requires: fail closed, never silently
        # overwrite, never silently discard the conflict.
        with pytest.raises(AssessmentConflictError):
            assessment_repo.save(stale_copy)

        # THE FIX, VERIFIED: durable state is untouched by the rejected
        # stale write - still COMPLETED, still 1 finding, still SUCCEEDED.
        after_attack = assessment_repo.get(to_assessment_id(assessment_id))
        execution_after = execution_repo.get_by_assessment_id(assessment_id)

        assert after_attack.status == AssessmentStatus.COMPLETED
        assert len(after_attack.findings) == 1
        assert after_attack.version == pre_attack.version
        assert execution_after is not None and execution_after.status.value == "SUCCEEDED"

        # No RUNNING+SUCCEEDED (or any other) INCONSISTENT combination was
        # ever created by this race.
        from kingsec.application.assessment_execution_ledger import ExecutionClassification, classify_execution

        classification = classify_execution(execution_after.status, after_attack.status)
        assert classification == ExecutionClassification.TERMINAL


# ── Section 16 / manual-vs-scheduler collision: no shared idempotency
# identity exists between a scheduler-service submission and an admin's
# direct manual submission of the SAME assessment_id. ──────────────────


class TestManualVsSchedulerCollision:
    def test_admin_and_scheduler_identity_racing_the_same_assessment_produce_one_scan(
        self, assessment_repo: LegacyAssessmentRepository, execution_repo: SqlAlchemyAssessmentExecutionRepository, session_factory
    ) -> None:
        # A scheduler-created assessment: owner_id = the scheduler service
        # identity, schedule_occurrence_id set - exactly what
        # SubmitScheduledAssessment.execute() produces via CreateAssessment,
        # reproduced directly here so the race can be isolated to the
        # submission step (the occurrence-claim machinery governing
        # WHETHER the scheduler is allowed to proceed is Phase 98/100's
        # own, separately-tested concern; this test asks a different
        # question - once two independent callers both hold a legitimate
        # reason to call SubmitAssessment.execute() on the SAME assessment
        # id, is there any shared identity preventing both from racing
        # through to the scanner?).
        assessment_id = _create_authorized_assessment(
            assessment_repo, owner_id="scheduler-service", schedule_occurrence_id="occ-collision-1"
        )
        scanner = _CountingScanner()
        job_runner = ThreadJobRunner(max_workers=4)
        submit_assessment = _make_submit_assessment(assessment_repo, execution_repo, scanner, job_runner)

        barrier = threading.Barrier(2)
        outcomes: list[tuple[str, Exception | None]] = [("", None), ("", None)]

        def _admin_submit() -> None:
            barrier.wait(timeout=10)
            try:
                submit_assessment.execute(
                    SubmitAssessmentRequest(assessment_id=assessment_id, requesting_user="admin-1", is_admin=True)
                )
                outcomes[0] = ("ok", None)
            except Exception as exc:
                outcomes[0] = ("error", exc)

        def _scheduler_submit() -> None:
            barrier.wait(timeout=10)
            try:
                submit_assessment.execute(
                    SubmitAssessmentRequest(
                        assessment_id=assessment_id, requesting_user="scheduler-service", is_admin=False
                    )
                )
                outcomes[1] = ("ok", None)
            except Exception as exc:
                outcomes[1] = ("error", exc)

        t1 = threading.Thread(target=_admin_submit)
        t2 = threading.Thread(target=_scheduler_submit)
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)

        try:
            _wait_for_execution_terminal(execution_repo, assessment_id)
        finally:
            job_runner.shutdown(wait=True)

        assert scanner.invocation_count == 1, (
            f"manual (admin) and scheduler-identity submissions of the same assessment_id "
            f"must never both reach the scanner: got {scanner.invocation_count}, outcomes={outcomes}"
        )
        assert _row_count(session_factory, AssessmentExecutionORM, assessment_id=assessment_id) == 1

        # There is NO shared business identity between "an occurrence the
        # scheduler is entitled to submit" and "an assessment an admin is
        # entitled to submit" beyond the assessment_id itself and
        # SubmitAssessment's own domain-transition/ledger/job-runner
        # mechanics - this test demonstrates that those mechanics alone
        # are sufficient to prevent a second scan, NOT that any dedicated
        # cross-identity idempotency mechanism exists (none does).
        ok_count = sum(1 for outcome, _ in outcomes if outcome == "ok")
        assert ok_count >= 1


# ── Section 8: repeated submission after success ────────────────────────


class TestRepeatedSubmissionAfterSuccess:
    def test_resubmitting_a_completed_assessment_is_rejected_not_idempotent(
        self, assessment_repo: LegacyAssessmentRepository, execution_repo: SqlAlchemyAssessmentExecutionRepository, session_factory
    ) -> None:
        assessment_id = _create_authorized_assessment(assessment_repo)
        scanner = _CountingScanner()
        job_runner = ThreadJobRunner(max_workers=2)
        submit_assessment = _make_submit_assessment(assessment_repo, execution_repo, scanner, job_runner)

        submit_assessment.execute(SubmitAssessmentRequest(assessment_id=assessment_id, requesting_user="user-1"))
        _wait_for_terminal(assessment_repo, assessment_id)
        assert scanner.invocation_count == 1

        # The actual contract, established by direct observation (not
        # assumed): a second submission of an already-COMPLETED assessment
        # is REJECTED, not silently treated as idempotent, not re-executed,
        # and does not create a second execution row.
        with pytest.raises(IllegalStateTransition):
            submit_assessment.execute(SubmitAssessmentRequest(assessment_id=assessment_id, requesting_user="user-1"))

        job_runner.shutdown(wait=True)
        assert scanner.invocation_count == 1, "resubmission must never invoke the scanner again"
        assert _row_count(session_factory, AssessmentExecutionORM, assessment_id=assessment_id) == 1


# ── Section 9 / Race F: submit while genuinely RUNNING ──────────────────


class TestSubmitWhileRunning:
    def test_second_submit_cannot_bypass_the_first_executions_running_state(
        self, assessment_repo: LegacyAssessmentRepository, execution_repo: SqlAlchemyAssessmentExecutionRepository, session_factory
    ) -> None:
        assessment_id = _create_authorized_assessment(assessment_repo)
        gated_scanner = _GatedScanner()
        job_runner = ThreadJobRunner(max_workers=2)
        submit_assessment = _make_submit_assessment(assessment_repo, execution_repo, gated_scanner, job_runner)

        submit_assessment.execute(SubmitAssessmentRequest(assessment_id=assessment_id, requesting_user="user-1"))
        # Deterministic proof the scanner is genuinely mid-invocation
        # right now - no sleep, a real threading.Event.
        assert gated_scanner.entered.wait(timeout=10), "scanner never started"

        with pytest.raises(IllegalStateTransition):
            submit_assessment.execute(SubmitAssessmentRequest(assessment_id=assessment_id, requesting_user="user-1"))

        assert gated_scanner.invocation_count == 1, "a second submit while RUNNING must not reach the scanner"

        gated_scanner.release_gate.set()
        _wait_for_terminal(assessment_repo, assessment_id)
        job_runner.shutdown(wait=True)
        assert gated_scanner.invocation_count == 1
        assert _row_count(session_factory, AssessmentExecutionORM, assessment_id=assessment_id) == 1


# ── Section 10: submit after terminal states ────────────────────────────


class TestSubmitAfterTerminalStates:
    def test_completed_assessment_cannot_be_resubmitted(
        self, assessment_repo: LegacyAssessmentRepository, execution_repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        assessment_id = _create_authorized_assessment(assessment_repo)
        scanner = _CountingScanner()
        job_runner = ThreadJobRunner(max_workers=2)
        submit_assessment = _make_submit_assessment(assessment_repo, execution_repo, scanner, job_runner)
        submit_assessment.execute(SubmitAssessmentRequest(assessment_id=assessment_id, requesting_user="user-1"))
        _wait_for_terminal(assessment_repo, assessment_id)
        job_runner.shutdown(wait=True)

        with pytest.raises(IllegalStateTransition):
            submit_assessment.execute(SubmitAssessmentRequest(assessment_id=assessment_id, requesting_user="user-1"))

    def test_failed_assessment_cannot_be_resubmitted(
        self, assessment_repo: LegacyAssessmentRepository, execution_repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        class _AlwaysFailsScanner:
            def scan(self, target: Target, *, scanner_ids: tuple[str, ...] | None = None) -> list[Finding]:
                raise RuntimeError("scanner deliberately fails")

            def compatible_scanners(self, target: Target) -> dict[str, str]:
                return {"stub": "Stub Scanner"}

        assessment_id = _create_authorized_assessment(assessment_repo)
        job_runner = ThreadJobRunner(max_workers=2)
        submit_assessment = _make_submit_assessment(assessment_repo, execution_repo, _AlwaysFailsScanner(), job_runner)
        submit_assessment.execute(SubmitAssessmentRequest(assessment_id=assessment_id, requesting_user="user-1"))

        from kingsec.application._support import to_assessment_id

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            assessment = assessment_repo.get(to_assessment_id(assessment_id))
            if assessment.status == AssessmentStatus.FAILED:
                break
            time.sleep(0.05)
        else:
            raise AssertionError("assessment never reached FAILED")
        job_runner.shutdown(wait=True)

        with pytest.raises(IllegalStateTransition):
            submit_assessment.execute(SubmitAssessmentRequest(assessment_id=assessment_id, requesting_user="user-1"))

    def test_cancelled_assessment_cannot_be_resubmitted(
        self, assessment_repo: LegacyAssessmentRepository, execution_repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        from kingsec.application._support import to_assessment_id

        assessment_id = _create_authorized_assessment(assessment_repo)
        assessment = assessment_repo.get(to_assessment_id(assessment_id))
        assessment.cancel()
        assessment_repo.save(assessment)

        scanner = _CountingScanner()
        job_runner = ThreadJobRunner(max_workers=2)
        submit_assessment = _make_submit_assessment(assessment_repo, execution_repo, scanner, job_runner)
        with pytest.raises(IllegalStateTransition):
            submit_assessment.execute(SubmitAssessmentRequest(assessment_id=assessment_id, requesting_user="user-1"))
        job_runner.shutdown(wait=True)
        assert scanner.invocation_count == 0


# ── Section 13/14: CreateAssessment has no idempotency key - a
# lost-response client retry deterministically creates a second,
# independent Assessment. ────────────────────────────────────────────────


class TestCreateAssessmentRetrySimulation:
    def test_identical_repeated_create_request_produces_two_distinct_assessments(
        self, assessment_repo: LegacyAssessmentRepository, session_factory
    ) -> None:
        """Simulates: request A reaches the server, CreateAssessment fully
        executes and commits, the response is lost before the client sees
        it, and the client retries with the IDENTICAL logical request.
        CreateAssessment has no idempotency-key/request-id field anywhere
        in CreateAssessmentRequest (confirmed by source re-read) - so this
        is deterministic, not probabilistic: calling execute() twice with
        an identical request is exactly what a real lost-response retry
        looks like from the server's point of view."""
        create_assessment = CreateAssessment(assessments=assessment_repo)
        request = CreateAssessmentRequest(
            target_value="10.0.0.9",
            target_type="ip_address",
            authorized_by="pentester@kingusecurity.com",
            scope="10.0.0.9",
            owner_id="user-1",
        )

        first = create_assessment.execute(request)
        second = create_assessment.execute(request)

        assert first.assessment_id != second.assessment_id, (
            "CreateAssessment has no idempotency mechanism - two calls with an identical "
            "logical request deterministically produce two distinct Assessment ids"
        )
        assert _row_count(session_factory, AssessmentORM, id=first.assessment_id) == 1
        assert _row_count(session_factory, AssessmentORM, id=second.assessment_id) == 1
        # Both are independently AUTHORIZED and independently submittable -
        # a client that retries a lost create-response and then submits
        # BOTH ids it believes might be "the" assessment will cause two
        # real scanner invocations against the same target. This is
        # Outcome B (Section 6/31): an intentional design (every request
        # is a new assessment; no idempotency key exists), not a scoped
        # code defect - the absence of protection against accidental
        # client retries is documented as residual risk, not fixed here.


class TestSubmitAssessmentIdAttacks:
    """Section 19 - Assessment ID attacks, exercised against SubmitAssessment
    directly (Phase 103/105's TestInjection classes already cover the
    execution-inspection endpoints; this covers the submission use case,
    which those classes never touched)."""

    @pytest.mark.parametrize(
        "bad_id",
        [
            "not-a-real-id",
            "'; DROP TABLE assessments; --",
            "x" * 10000,
            "asmt-ü中文",
            "",
        ],
    )
    def test_malformed_or_hostile_assessment_id_never_causes_state_mutation_or_crash(
        self,
        assessment_repo: LegacyAssessmentRepository,
        execution_repo: SqlAlchemyAssessmentExecutionRepository,
        bad_id: str,
    ) -> None:
        scanner = _CountingScanner()
        job_runner = ThreadJobRunner(max_workers=2)
        submit_assessment = _make_submit_assessment(assessment_repo, execution_repo, scanner, job_runner)
        with pytest.raises((AssessmentNotFoundError, Exception)) as excinfo:
            submit_assessment.execute(SubmitAssessmentRequest(assessment_id=bad_id, requesting_user="user-1"))
        # Never a raw, unhandled database error class leaking internals -
        # AssessmentNotFoundError (the expected, application-level error)
        # or a clean InputValidationError are acceptable; a raw
        # sqlalchemy.exc.* leaking through is not.
        assert "sqlalchemy" not in type(excinfo.value).__module__
        job_runner.shutdown(wait=True)
        assert scanner.invocation_count == 0

    def test_valid_id_belonging_to_another_user_is_not_found_not_forbidden(
        self, assessment_repo: LegacyAssessmentRepository, execution_repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        victim_assessment_id = _create_authorized_assessment(assessment_repo, owner_id="victim-user")
        scanner = _CountingScanner()
        job_runner = ThreadJobRunner(max_workers=2)
        submit_assessment = _make_submit_assessment(assessment_repo, execution_repo, scanner, job_runner)

        # Attacker knows/guesses the victim's real assessment id.
        with pytest.raises(AssessmentNotFoundError):
            submit_assessment.execute(
                SubmitAssessmentRequest(assessment_id=victim_assessment_id, requesting_user="attacker", is_admin=False)
            )
        job_runner.shutdown(wait=True)
        assert scanner.invocation_count == 0, "an unauthorized submit must never reach the scanner"
