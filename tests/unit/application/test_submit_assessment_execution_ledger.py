"""KSEC-102-01: SubmitAssessment's real wiring to the durable
AssessmentExecutionRepositoryPort.

Real on-disk SQLite + the real SqlAlchemyAssessmentExecutionRepository
throughout (never a mock/fake repository or fake locking - KSEC-102-01
Step 22) - only ScannerPort/JobRunner are the same fakes already
established in test_submit_assessment.py, since a unit test has no
business invoking real scanner binaries.
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kingsec.application.assessment_execution_ledger import AssessmentExecutionStatus
from kingsec.application.dto import SubmitAssessmentRequest
from kingsec.application.errors import AssessmentNotFoundError
from kingsec.application.submit_assessment import SubmitAssessment
from kingsec.domain import Assessment, AssessmentId, Finding, Target, TargetType
from kingsec.domain.authorization import Authorization
from kingsec.domain.enums import AssessmentStatus
from kingsec.infrastructure.persistence.models import Base
from kingsec.infrastructure.persistence.repositories.assessment_execution import (
    SqlAlchemyAssessmentExecutionRepository,
)


class FakeAssessmentRepository:
    def __init__(self, assessments: dict[str, Assessment] | None = None) -> None:
        self._assessments = assessments or {}
        self.saved: list[Assessment] = []

    def get(self, assessment_id: AssessmentId) -> Assessment:
        a = self._assessments.get(str(assessment_id))
        if a is None:
            raise AssessmentNotFoundError(str(assessment_id))
        return a

    def save(self, assessment: Assessment) -> None:
        self._assessments[str(assessment.id)] = assessment
        self.saved.append(assessment)

    def list(self, *, limit: int = 50, offset: int = 0) -> list[Assessment]:
        return list(self._assessments.values())[offset : offset + limit]

    def delete(self, assessment_id: AssessmentId) -> None:
        del self._assessments[str(assessment_id)]


class CountingScanner:
    """Counts real scan() invocations - the direct proof required by Step
    21 Case F ("critically verify scanner invocation count = 1, not merely
    database status = CLAIMED")."""

    def __init__(self, findings: list[Finding] | None = None) -> None:
        self._findings = findings or []
        self.invocation_count = 0
        self._lock = threading.Lock()

    def scan(self, target: Any) -> list[Finding]:
        with self._lock:
            self.invocation_count += 1
        return list(self._findings)

    def compatible_scanners(self, target: Any) -> dict[str, str]:
        return {"fake": "Fake Scanner"}


class FailingScanner:
    def scan(self, target: Any) -> list[Finding]:
        raise RuntimeError("simulated scanner failure")

    def compatible_scanners(self, target: Any) -> dict[str, str]:
        return {"fake": "Fake Scanner"}


class RecordingJobRunner:
    def __init__(self, run_inline: bool = True) -> None:
        self._jobs: dict[str, Any] = {}
        self._run_inline = run_inline

    def submit(self, job_id: str, fn: Any, *args: Any, **kwargs: Any) -> None:
        self._jobs[job_id] = fn
        if self._run_inline:
            fn()

    def is_running(self, job_id: str) -> bool:
        return job_id in self._jobs

    def shutdown(self, wait: bool = True) -> None:
        pass

    def run_pending(self, job_id: str) -> None:
        self._jobs[job_id]()


def _make_authorized_assessment(assessment_id: str = "asmt-1", target: str = "10.0.0.5") -> Assessment:
    a = Assessment(assessment_id=AssessmentId(assessment_id), target=Target(target, TargetType.IP_ADDRESS))
    a.authorize(Authorization("test-user", datetime.now(UTC), scope="test-scope"))
    return a


@pytest.fixture
def session_factory(tmp_path: Path):
    db_path = tmp_path / f"submit-assessment-ledger-{uuid.uuid4().hex}.sqlite3"
    engine = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def execution_repo(session_factory) -> SqlAlchemyAssessmentExecutionRepository:
    return SqlAlchemyAssessmentExecutionRepository(session_factory)


class TestRequestedRecordCreatedBeforeExecution:
    def test_execute_creates_a_durable_requested_record_before_the_scan_runs(
        self, execution_repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        """Step 14's required property: every assessment that enters the
        real execution path has a durable execution record before
        execution is attempted - proven with a non-inline job runner so the
        background scan never actually runs during this assertion."""
        assessment = _make_authorized_assessment()
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        job_runner = RecordingJobRunner(run_inline=False)

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=CountingScanner(),
            job_runner=job_runner,
            execution_ledger=execution_repo,
        )
        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-1", is_admin=True))

        execution = execution_repo.get_by_assessment_id("asmt-1")
        assert execution is not None
        assert execution.status == AssessmentExecutionStatus.REQUESTED


class TestHappyPathReachesTerminalLedgerState:
    def test_a_successful_scan_ends_with_a_succeeded_execution_record(
        self, execution_repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        assessment = _make_authorized_assessment()
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        scanner = CountingScanner()

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=scanner,
            job_runner=RecordingJobRunner(run_inline=True),
            execution_ledger=execution_repo,
        )
        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-1", is_admin=True))

        assert scanner.invocation_count == 1
        execution = execution_repo.get_by_assessment_id("asmt-1")
        assert execution is not None
        assert execution.status == AssessmentExecutionStatus.SUCCEEDED
        assert repo.get(AssessmentId("asmt-1")).status == AssessmentStatus.COMPLETED

    def test_a_failing_scan_ends_with_a_failed_execution_record(
        self, execution_repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        assessment = _make_authorized_assessment()
        repo = FakeAssessmentRepository({str(assessment.id): assessment})

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=FailingScanner(),
            job_runner=RecordingJobRunner(run_inline=True),
            execution_ledger=execution_repo,
        )
        use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-1", is_admin=True))

        execution = execution_repo.get_by_assessment_id("asmt-1")
        assert execution is not None
        assert execution.status == AssessmentExecutionStatus.FAILED
        assert repo.get(AssessmentId("asmt-1")).status == AssessmentStatus.FAILED


class TestLedgerIsOptional:
    def test_execute_behaves_identically_with_no_execution_ledger_configured(self) -> None:
        """Every existing call site that constructs SubmitAssessment
        without an execution_ledger (the entire pre-Phase-102 test suite)
        must keep behaving exactly as before."""
        assessment = _make_authorized_assessment()
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        scanner = CountingScanner()

        use_case = SubmitAssessment(
            assessments=repo,
            scanner=scanner,
            job_runner=RecordingJobRunner(run_inline=True),
        )
        response = use_case.execute(SubmitAssessmentRequest(assessment_id="asmt-1", is_admin=True))

        assert response.status == "completed"
        assert scanner.invocation_count == 1


class TestClaimRaceStopsScannerInvocation:
    def test_a_lost_claim_race_never_invokes_the_scanner(
        self, execution_repo: SqlAlchemyAssessmentExecutionRepository
    ) -> None:
        """KSEC-102-01 Step 15/21 Case F: critically verify scanner
        invocation count, not merely database status. This directly calls
        the module-level ``_execute_scan`` twice for the SAME assessment
        (bypassing ThreadJobRunner's own already-running guard, which would
        otherwise make this scenario unreachable through the real
        production call graph - see the Phase 102 report's honesty note on
        this) to prove the ledger's own claim mechanism, independently,
        stops a second caller before it ever reaches the scanner."""
        from kingsec.application.submit_assessment import _execute_scan

        assessment = _make_authorized_assessment()
        assessment.start()
        repo = FakeAssessmentRepository({str(assessment.id): assessment})
        scanner = CountingScanner()
        execution_repo.create_requested("asmt-1")

        barrier = threading.Barrier(2)
        original_try_claim = execution_repo.try_claim

        def _synchronized_try_claim(execution_id: str, expected_version: int) -> int | None:
            barrier.wait(timeout=5)
            return original_try_claim(execution_id, expected_version)

        execution_repo.try_claim = _synchronized_try_claim  # type: ignore[method-assign]

        threads = [
            threading.Thread(
                target=_execute_scan,
                kwargs={
                    "assessment_id": AssessmentId("asmt-1"),
                    "assessments": repo,
                    "scanner": scanner,
                    "ai": None,
                    "execution_ledger": execution_repo,
                },
            )
            for _ in range(2)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert scanner.invocation_count == 1, (
            f"expected exactly 1 real scanner invocation, observed {scanner.invocation_count} - "
            "the losing claimant must stop before invoking the scanner"
        )
        execution = execution_repo.get_by_assessment_id("asmt-1")
        assert execution.status == AssessmentExecutionStatus.SUCCEEDED
