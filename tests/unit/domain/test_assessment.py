"""Assessment aggregate: the authorization gate and lifecycle rules."""

from __future__ import annotations

import pytest

from kingsec.domain import (
    Assessment,
    AssessmentId,
    AssessmentStatus,
    IllegalStateTransition,
    InvariantViolation,
    Severity,
)
from tests.unit.domain.conftest import make_finding


class TestAuthorizationGate:
    """The single most important rule: no start without authorization."""

    def test_new_assessment_is_draft_and_unauthorized(self, draft: Assessment) -> None:
        assert draft.status is AssessmentStatus.DRAFT
        assert draft.is_authorized is False

    def test_cannot_start_without_authorization(self, draft: Assessment) -> None:
        with pytest.raises(IllegalStateTransition) as excinfo:
            draft.start()
        assert "authorized before it can start" in str(excinfo.value)
        assert excinfo.value.current is AssessmentStatus.DRAFT

    def test_authorize_then_start_succeeds(self, draft, authorization) -> None:
        draft.authorize(authorization)
        assert draft.status is AssessmentStatus.AUTHORIZED
        assert draft.is_authorized is True
        draft.start()
        assert draft.status is AssessmentStatus.RUNNING

    def test_authorize_requires_authorization_object(self, draft: Assessment) -> None:
        with pytest.raises(InvariantViolation):
            draft.authorize("yes please")  # type: ignore[arg-type]


class TestLifecycle:
    def test_happy_path_to_completed(self, running: Assessment) -> None:
        running.record_finding(make_finding())
        running.complete()
        assert running.status is AssessmentStatus.COMPLETED

    def test_cannot_complete_before_running(self, draft: Assessment) -> None:
        with pytest.raises(IllegalStateTransition):
            draft.complete()

    def test_cannot_authorize_twice(self, draft, authorization) -> None:
        draft.authorize(authorization)
        with pytest.raises(IllegalStateTransition):
            draft.authorize(authorization)

    def test_fail_records_reason(self, running: Assessment) -> None:
        running.fail("scanner crashed")
        assert running.status is AssessmentStatus.FAILED
        assert running.failure_reason == "scanner crashed"

    def test_fail_requires_reason(self, running: Assessment) -> None:
        with pytest.raises(InvariantViolation):
            running.fail("   ")

    def test_cancel_from_draft(self, draft: Assessment) -> None:
        draft.cancel()
        assert draft.status is AssessmentStatus.CANCELLED

    def test_terminal_states_are_terminal(self, running: Assessment) -> None:
        running.complete()
        with pytest.raises(IllegalStateTransition):
            running.cancel()


class TestFindingRules:
    def test_cannot_record_finding_before_running(self, draft: Assessment) -> None:
        with pytest.raises(IllegalStateTransition):
            draft.record_finding(make_finding())

    def test_cannot_record_finding_after_completion(self, running: Assessment) -> None:
        running.complete()
        with pytest.raises(IllegalStateTransition):
            running.record_finding(make_finding())

    def test_duplicate_finding_id_is_rejected(self, running: Assessment) -> None:
        finding = make_finding()
        running.record_finding(finding)
        with pytest.raises(InvariantViolation, match="duplicate finding id"):
            running.record_finding(finding)

    def test_findings_view_is_immutable_tuple(self, running: Assessment) -> None:
        running.record_finding(make_finding())
        assert isinstance(running.findings, tuple)

    def test_highest_severity(self, running: Assessment) -> None:
        assert running.highest_severity is None
        running.record_finding(make_finding(Severity.LOW))
        running.record_finding(make_finding(Severity.CRITICAL))
        running.record_finding(make_finding(Severity.MEDIUM))
        assert running.highest_severity is Severity.CRITICAL


class TestIdentity:
    def test_equality_is_by_id(self, target) -> None:
        aid = AssessmentId.generate()
        a = Assessment(aid, target)
        b = Assessment(aid, target)
        assert a == b
        assert hash(a) == hash(b)
