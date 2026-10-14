
from kingsec.application.assessment_execution import (
    AssessmentExecutionEngine,
    ExecutionPhase,
    ScannerPlanEntry,
)
from kingsec.domain.enums import ScannerRunState


class TestAssessmentExecutionEngine:
    def setup_method(self) -> None:
        self.engine = AssessmentExecutionEngine()

    def test_start_execution_creates_state(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap", "semgrep": "Semgrep"})
        state = self.engine.get_state("assess-1")
        assert state is not None
        assert state.assessment_id == "assess-1"
        assert state.phase == ExecutionPhase.PREPARING
        assert len(state.scanner_progress) == 2

    def test_start_scanner(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap"})
        self.engine.start_scanner("assess-1", "nmap")
        state = self.engine.get_state("assess-1")
        assert state is not None
        scanner = state.scanner_progress[0]
        assert scanner.status == ScannerRunState.RUNNING
        assert scanner.start_time is not None

    def test_complete_scanner(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap"})
        self.engine.start_scanner("assess-1", "nmap")
        self.engine.complete_scanner("assess-1", "nmap", findings_count=5)
        state = self.engine.get_state("assess-1")
        assert state is not None
        scanner = state.scanner_progress[0]
        assert scanner.status == ScannerRunState.SUCCEEDED
        assert scanner.findings_count == 5
        assert scanner.end_time is not None

    def test_fail_scanner(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap"})
        self.engine.start_scanner("assess-1", "nmap")
        self.engine.fail_scanner("assess-1", "nmap", "timeout")
        state = self.engine.get_state("assess-1")
        assert state is not None
        scanner = state.scanner_progress[0]
        assert scanner.status == ScannerRunState.FAILED
        assert scanner.error == "timeout"

    def test_skip_scanner(self) -> None:
        # Phase 2A Correction 2b: skip_scanner() no longer exists - a
        # non-selected scanner is now seeded directly in its terminal
        # skip state via set_scanner_plan(), never mutated into that
        # state after the fact.
        self.engine.start_execution("assess-1", {})
        self.engine.set_scanner_plan(
            "assess-1",
            (
                ScannerPlanEntry(scanner_id="nmap", name="Nmap", selected=True),
                ScannerPlanEntry(
                    scanner_id="zap",
                    name="OWASP ZAP",
                    selected=False,
                    skip_state=ScannerRunState.SKIPPED_BINARY_MISSING,
                    skip_reason="Not installed",
                ),
            ),
        )
        state = self.engine.get_state("assess-1")
        assert state is not None
        zap = next(s for s in state.scanner_progress if s.scanner_id == "zap")
        assert zap.status == ScannerRunState.SKIPPED_BINARY_MISSING
        assert zap.skipped_reason == "Not installed"

    def test_transition_phase(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap"})
        self.engine.transition_phase("assess-1", ExecutionPhase.RUNNING_SCANNERS)
        state = self.engine.get_state("assess-1")
        assert state is not None
        assert state.phase == ExecutionPhase.RUNNING_SCANNERS

    def test_cancel_execution(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap"})
        self.engine.transition_phase("assess-1", ExecutionPhase.RUNNING_SCANNERS)
        result = self.engine.cancel_execution("assess-1")
        assert result is True
        state = self.engine.get_state("assess-1")
        assert state is not None
        assert state.phase == ExecutionPhase.CANCELLED
        assert state.completed_at is not None

    def test_cancel_terminal_fails(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap"})
        self.engine.transition_phase("assess-1", ExecutionPhase.RUNNING_SCANNERS)
        self.engine.transition_phase("assess-1", ExecutionPhase.CORRELATING)
        self.engine.transition_phase("assess-1", ExecutionPhase.REPORTING)
        self.engine.transition_phase("assess-1", ExecutionPhase.COMPLETED)
        result = self.engine.cancel_execution("assess-1")
        assert result is False

    def test_fail_execution(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap"})
        self.engine.fail_execution("assess-1", "Something went wrong")
        state = self.engine.get_state("assess-1")
        assert state is not None
        assert state.phase == ExecutionPhase.FAILED
        assert state.error_message == "Something went wrong"

    def test_get_events(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap"})
        events = self.engine.get_events("assess-1")
        assert len(events) >= 1
        assert events[0].event_type == "execution.started"

    def test_get_progress(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap"})
        progress = self.engine.get_progress("assess-1")
        assert progress is not None
        assert progress >= 0.0

    def test_is_cancelled(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap"})
        assert self.engine.is_cancelled("assess-1") is False
        self.engine.cancel_execution("assess-1")
        assert self.engine.is_cancelled("assess-1") is True

    def test_cleanup(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap"})
        assert self.engine.get_state("assess-1") is not None
        self.engine.cleanup("assess-1")
        assert self.engine.get_state("assess-1") is None

    def test_unknown_assessment_returns_none(self) -> None:
        assert self.engine.get_state("nonexistent") is None
        assert self.engine.get_progress("nonexistent") is None
        assert self.engine.is_cancelled("nonexistent") is False
        assert self.engine.get_events("nonexistent") == ()


class TestCancellationSignal:
    """The cancellation event: the signal that actually stops scan work.

    Regression coverage for the defect where cancel returned 200 OK while
    scanners kept running: the phase flip existed, but nothing the scan
    path observed. These tests pin the event lifecycle the orchestrator
    and subprocess runner now depend on.
    """

    def setup_method(self) -> None:
        self.engine = AssessmentExecutionEngine()

    def test_cancel_execution_sets_cancellation_event(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap"})
        event = self.engine.cancellation_event("assess-1")
        assert event.is_set() is False
        assert self.engine.cancel_execution("assess-1") is True
        assert event.is_set() is True

    def test_cancellation_event_is_stable_object(self) -> None:
        self.engine.start_execution("assess-1", {})
        assert self.engine.cancellation_event("assess-1") is self.engine.cancellation_event("assess-1")

    def test_cancellation_event_unknown_assessment_returns_unset_event(self) -> None:
        event = self.engine.cancellation_event("nonexistent")
        assert event.is_set() is False

    def test_failed_cancel_does_not_set_event(self) -> None:
        # Cancelling a terminal execution returns False and must not
        # signal anything: there is no scan left to stop.
        self.engine.start_execution("assess-1", {})
        self.engine.transition_phase("assess-1", ExecutionPhase.RUNNING_SCANNERS)
        self.engine.transition_phase("assess-1", ExecutionPhase.CORRELATING)
        self.engine.transition_phase("assess-1", ExecutionPhase.REPORTING)
        self.engine.transition_phase("assess-1", ExecutionPhase.COMPLETED)
        assert self.engine.cancel_execution("assess-1") is False
        assert self.engine.cancellation_event("assess-1").is_set() is False

    def test_cancel_scanner_marks_pending_as_cancelled(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap", "nikto": "Nikto"})
        self.engine.cancel_scanner("assess-1", "nmap", "assessment cancelled by user")
        state = self.engine.get_state("assess-1")
        assert state is not None
        by_id = {s.scanner_id: s for s in state.scanner_progress}
        assert by_id["nmap"].status == ScannerRunState.FAILED
        assert by_id["nmap"].status.is_terminal
        assert "cancelled by user" in (by_id["nmap"].error or "")
        # The untouched scanner keeps its real state.
        assert by_id["nikto"].status == ScannerRunState.PENDING

    def test_cancel_scanner_keeps_terminal_outcome(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap"})
        self.engine.start_scanner("assess-1", "nmap")
        self.engine.complete_scanner("assess-1", "nmap", findings_count=3)
        self.engine.cancel_scanner("assess-1", "nmap", "assessment cancelled by user")
        state = self.engine.get_state("assess-1")
        assert state is not None
        by_id = {s.scanner_id: s for s in state.scanner_progress}
        assert by_id["nmap"].status == ScannerRunState.SUCCEEDED
        assert by_id["nmap"].findings_count == 3

    def test_cancel_scanner_emits_cancelled_event(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap"})
        self.engine.cancel_scanner("assess-1", "nmap", "assessment cancelled by user")
        event_types = [e.event_type for e in self.engine.get_events("assess-1")]
        assert "scanner.cancelled" in event_types

    def test_cancel_scanner_unknown_scanner_is_noop(self) -> None:
        self.engine.start_execution("assess-1", {"nmap": "Nmap"})
        self.engine.cancel_scanner("assess-1", "nope", "assessment cancelled by user")
        state = self.engine.get_state("assess-1")
        assert state is not None
        assert len(state.scanner_progress) == 1

    def test_cleanup_drops_cancel_event(self) -> None:
        self.engine.start_execution("assess-1", {})
        self.engine.cleanup("assess-1")
        # A fresh, never-set event: callers never special-case None.
        assert self.engine.cancellation_event("assess-1").is_set() is False
