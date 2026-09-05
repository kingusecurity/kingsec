"""KSEC-103-01: classify_execution() - pure, read-only classification of a
durable execution record against its Assessment's durable status.

No I/O anywhere in this file - these are pure-function tests of the exact
decision table the operator-inspection feature relies on. Real database/
join correctness is covered separately in
tests/unit/infrastructure/test_assessment_execution_inspection.py and the
HTTP-level tests in
tests/integration/adapters/inbound/web/test_execution_inspection_routes.py.
"""

from __future__ import annotations

import pytest

from kingsec.application.assessment_execution_ledger import (
    AssessmentExecutionStatus,
    ExecutionClassification,
    classify_execution,
)
from kingsec.domain.enums import AssessmentStatus


class TestUnresolved:
    """Phase 103 Test C/D/E: REQUESTED, CLAIMED, and RUNNING-while-the-
    assessment-is-still-RUNNING must all classify as UNRESOLVED - never
    silently treated as failed, never auto-retried."""

    def test_requested_with_running_assessment_is_unresolved(self) -> None:
        assert (
            classify_execution(AssessmentExecutionStatus.REQUESTED, AssessmentStatus.RUNNING)
            == ExecutionClassification.UNRESOLVED
        )

    def test_claimed_with_running_assessment_is_unresolved(self) -> None:
        assert (
            classify_execution(AssessmentExecutionStatus.CLAIMED, AssessmentStatus.RUNNING)
            == ExecutionClassification.UNRESOLVED
        )

    def test_running_with_running_assessment_is_unresolved(self) -> None:
        assert (
            classify_execution(AssessmentExecutionStatus.RUNNING, AssessmentStatus.RUNNING)
            == ExecutionClassification.UNRESOLVED
        )


class TestReconcilable:
    """Phase 103 Test F/G: RUNNING + durable terminal Assessment evidence
    (COMPLETED or FAILED) is safely reconcilable - reported, never
    silently mutated (this module contains no mutation at all)."""

    def test_running_with_completed_assessment_is_reconcilable(self) -> None:
        assert (
            classify_execution(AssessmentExecutionStatus.RUNNING, AssessmentStatus.COMPLETED)
            == ExecutionClassification.RECONCILABLE
        )

    def test_running_with_failed_assessment_is_reconcilable(self) -> None:
        assert (
            classify_execution(AssessmentExecutionStatus.RUNNING, AssessmentStatus.FAILED)
            == ExecutionClassification.RECONCILABLE
        )


class TestTerminal:
    """Phase 103 Test H: SUCCEEDED/FAILED executions whose Assessment
    status matches the expected corresponding terminal state are TERMINAL."""

    def test_succeeded_with_completed_assessment_is_terminal(self) -> None:
        assert (
            classify_execution(AssessmentExecutionStatus.SUCCEEDED, AssessmentStatus.COMPLETED)
            == ExecutionClassification.TERMINAL
        )

    def test_failed_with_failed_assessment_is_terminal(self) -> None:
        assert (
            classify_execution(AssessmentExecutionStatus.FAILED, AssessmentStatus.FAILED)
            == ExecutionClassification.TERMINAL
        )


class TestInconsistent:
    """Phase 103 Test I: contradictory durable facts must be reported
    conservatively, never silently reinterpreted or mutated."""

    def test_succeeded_with_running_assessment_is_inconsistent(self) -> None:
        assert (
            classify_execution(AssessmentExecutionStatus.SUCCEEDED, AssessmentStatus.RUNNING)
            == ExecutionClassification.INCONSISTENT
        )

    def test_failed_with_completed_assessment_is_inconsistent(self) -> None:
        assert (
            classify_execution(AssessmentExecutionStatus.FAILED, AssessmentStatus.COMPLETED)
            == ExecutionClassification.INCONSISTENT
        )

    def test_requested_with_completed_assessment_is_inconsistent(self) -> None:
        """An edge case not explicitly listed in Phase 103's own examples,
        but the same principle applies: durable terminal Assessment
        evidence appearing while the execution record claims the scanner
        was never even claimed yet is a contradiction, not ordinary
        unresolved ambiguity."""
        assert (
            classify_execution(AssessmentExecutionStatus.REQUESTED, AssessmentStatus.COMPLETED)
            == ExecutionClassification.INCONSISTENT
        )

    def test_claimed_with_failed_assessment_is_inconsistent(self) -> None:
        assert (
            classify_execution(AssessmentExecutionStatus.CLAIMED, AssessmentStatus.FAILED)
            == ExecutionClassification.INCONSISTENT
        )


class TestExhaustive:
    """Every (execution_status, assessment_status) combination must
    classify to exactly one value and never raise - an operator-facing
    inspection tool must not 500 on any durable state combination it can
    actually observe."""

    @pytest.mark.parametrize("execution_status", list(AssessmentExecutionStatus))
    @pytest.mark.parametrize("assessment_status", list(AssessmentStatus))
    def test_never_raises_and_always_returns_a_classification(
        self, execution_status: AssessmentExecutionStatus, assessment_status: AssessmentStatus
    ) -> None:
        result = classify_execution(execution_status, assessment_status)
        assert isinstance(result, ExecutionClassification)
