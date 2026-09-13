from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from kingsec.domain.enums import ScannerRunState

__all__ = [
    "AssessmentExecutionEngine",
    "AssessmentExecutionState",
    "ExecutionEvent",
    "ExecutionPhase",
    "ScannerPlanEntry",
    "ScannerProgress",
    "ScannerRunState",
]


class ExecutionPhase(StrEnum):
    PENDING = "pending"
    PREPARING = "preparing"
    RUNNING_SCANNERS = "running_scanners"
    CORRELATING = "correlating"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in (
            ExecutionPhase.COMPLETED,
            ExecutionPhase.FAILED,
            ExecutionPhase.CANCELLED,
        )

    @property
    def progress_percent(self) -> float:
        mapping: dict[ExecutionPhase, float] = {
            ExecutionPhase.PENDING: 0.0,
            ExecutionPhase.PREPARING: 5.0,
            ExecutionPhase.RUNNING_SCANNERS: 50.0,
            ExecutionPhase.CORRELATING: 85.0,
            ExecutionPhase.REPORTING: 95.0,
            ExecutionPhase.COMPLETED: 100.0,
            ExecutionPhase.FAILED: 100.0,
            ExecutionPhase.CANCELLED: 100.0,
        }
        return mapping.get(self, 0.0)


@dataclass(frozen=True, slots=True)
class ScannerPlanEntry:
    """One scanner's disposition, decided once, before dispatch begins.

    ``selected=True`` means the orchestrator will actually invoke this
    scanner (it starts life at PENDING, to be advanced by
    start/complete/fail/timeout). ``selected=False`` means it is seeded
    directly in its terminal ``skip_state`` and the orchestrator will
    never touch it — there is no "pending" window for a scanner that was
    never going to run (Phase 2A Correction 2b).
    """

    scanner_id: str
    name: str
    selected: bool
    skip_state: ScannerRunState | None = None
    skip_reason: str | None = None

    def __post_init__(self) -> None:
        if self.selected and self.skip_state is not None:
            raise ValueError("a selected scanner cannot also carry a skip_state")
        if not self.selected and (self.skip_state is None or not self.skip_state.is_skip):
            raise ValueError("a non-selected scanner must carry one of the SKIPPED_* states")


@dataclass(frozen=True, slots=True)
class ScannerProgress:
    scanner_id: str
    name: str
    status: ScannerRunState
    start_time: str | None = None
    end_time: str | None = None
    duration_seconds: float | None = None
    findings_count: int = 0
    warnings: tuple[str, ...] = ()
    error: str | None = None
    skipped_reason: str | None = None
    port_specification: str | None = None


@dataclass(frozen=True, slots=True)
class ExecutionEvent:
    event_type: str
    scanner_id: str | None
    timestamp: str
    message: str
    progress_percent: float


@dataclass(frozen=True, slots=True)
class AssessmentExecutionState:
    assessment_id: str
    phase: ExecutionPhase
    progress_percent: float
    scanner_progress: tuple[ScannerProgress, ...]
    events: tuple[ExecutionEvent, ...]
    started_at: str | None
    completed_at: str | None
    error_message: str | None = None


_VALID_TRANSITIONS: dict[ExecutionPhase, set[ExecutionPhase]] = {
    ExecutionPhase.PENDING: {ExecutionPhase.PREPARING, ExecutionPhase.CANCELLED},
    ExecutionPhase.PREPARING: {ExecutionPhase.RUNNING_SCANNERS, ExecutionPhase.FAILED, ExecutionPhase.CANCELLED},
    ExecutionPhase.RUNNING_SCANNERS: {ExecutionPhase.CORRELATING, ExecutionPhase.FAILED, ExecutionPhase.CANCELLED},
    ExecutionPhase.CORRELATING: {ExecutionPhase.REPORTING, ExecutionPhase.FAILED, ExecutionPhase.CANCELLED},
    ExecutionPhase.REPORTING: {ExecutionPhase.COMPLETED, ExecutionPhase.FAILED, ExecutionPhase.CANCELLED},
    ExecutionPhase.COMPLETED: set(),
    ExecutionPhase.FAILED: set(),
    ExecutionPhase.CANCELLED: set(),
}


class AssessmentExecutionEngine:
    """In-memory execution lifecycle tracker for assessments.

    Tracks granular execution phases, per-scanner progress, and ordered
    events for each assessment.  Thread-safe via ``threading.Lock``.

    No domain entities are modified.  This is a pure application-layer
    service that maintains ephemeral state.
    """

    def __init__(self) -> None:
        self._states: dict[str, _InternalState] = {}
        self._lock = threading.Lock()

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start_execution(self, assessment_id: str, scanner_names: dict[str, str]) -> None:
        """Begin tracking an assessment execution.

        Args:
            assessment_id: The assessment being executed.
            scanner_names: Mapping of scanner_id -> human-readable name
                for all scanners in the execution plan. Callers that
                don't yet know the plan (the common case — see
                ``set_scanner_plan()``) pass an empty dict here.
        """
        now = _now()
        scanners = tuple(
            ScannerProgress(
                scanner_id=sid,
                name=name,
                status=ScannerRunState.PENDING,
            )
            for sid, name in scanner_names.items()
        )
        state = _InternalState(
            assessment_id=assessment_id,
            phase=ExecutionPhase.PREPARING,
            scanner_progress={s.scanner_id: s for s in scanners},
            events=[],
            started_at=now,
        )
        state.events.append(ExecutionEvent(
            event_type="execution.started",
            scanner_id=None,
            timestamp=now,
            message="Assessment execution started",
            progress_percent=ExecutionPhase.PREPARING.progress_percent,
        ))
        with self._lock:
            self._states[assessment_id] = state

    def set_scanner_plan(self, assessment_id: str, plan: tuple[ScannerPlanEntry, ...]) -> None:
        """Populate the scanner list for an execution already started via
        start_execution(), from a complete, per-scanner plan decision.

        Every entry in ``plan`` is seeded immediately: a selected scanner
        starts at PENDING (to be advanced as the orchestrator dispatches
        it); a non-selected scanner is created ALREADY in its terminal
        skip state. This is what makes "pending forever" structurally
        impossible (Phase 2A Correction 2b/3) — a scanner that will never
        be dispatched never has a pending window to get stuck in, because
        it is never pending in the first place.

        No-ops if start_execution() was never called for this id.
        """
        now = _now()
        entries: dict[str, ScannerProgress] = {}
        for entry in plan:
            if entry.selected:
                entries[entry.scanner_id] = ScannerProgress(
                    scanner_id=entry.scanner_id,
                    name=entry.name,
                    status=ScannerRunState.PENDING,
                )
            else:
                assert entry.skip_state is not None  # enforced by ScannerPlanEntry.__post_init__
                entries[entry.scanner_id] = ScannerProgress(
                    scanner_id=entry.scanner_id,
                    name=entry.name,
                    status=entry.skip_state,
                    end_time=now,
                    skipped_reason=entry.skip_reason,
                )
        with self._lock:
            state = self._states.get(assessment_id)
            if state is None:
                return
            state.scanner_progress = entries
            for entry in plan:
                if not entry.selected:
                    state.events.append(ExecutionEvent(
                        event_type="scanner.skipped",
                        scanner_id=entry.scanner_id,
                        timestamp=now,
                        message=f"Scanner {entry.name} skipped: {entry.skip_reason}",
                        progress_percent=_calc_progress(state),
                    ))

    def transition_phase(self, assessment_id: str, target: ExecutionPhase, message: str = "") -> None:
        """Transition the execution to a new phase."""
        with self._lock:
            state = self._states.get(assessment_id)
            if state is None:
                return
            if target not in _VALID_TRANSITIONS.get(state.phase, set()):
                return
            now = _now()
            state.phase = target
            if not message:
                message = f"Phase: {target.value.replace('_', ' ').title()}"
            state.events.append(ExecutionEvent(
                event_type=f"execution.{target.value}",
                scanner_id=None,
                timestamp=now,
                message=message,
                progress_percent=target.progress_percent,
            ))
            if target.is_terminal:
                state.completed_at = now

    def start_scanner(self, assessment_id: str, scanner_id: str) -> None:
        """Mark a scanner as currently running."""
        with self._lock:
            state = self._states.get(assessment_id)
            if state is None:
                return
            existing = state.scanner_progress.get(scanner_id)
            if existing is None or existing.status != ScannerRunState.PENDING:
                return
            now = _now()
            state.scanner_progress[scanner_id] = ScannerProgress(
                scanner_id=existing.scanner_id,
                name=existing.name,
                status=ScannerRunState.RUNNING,
                start_time=now,
            )
            state.events.append(ExecutionEvent(
                event_type="scanner.started",
                scanner_id=scanner_id,
                timestamp=now,
                message=f"Scanner {existing.name} started",
                progress_percent=_calc_progress(state),
            ))

    def complete_scanner(
        self,
        assessment_id: str,
        scanner_id: str,
        *,
        findings_count: int = 0,
        warnings: tuple[str, ...] = (),
        port_specification: str | None = None,
    ) -> None:
        """Mark a scanner as successfully completed."""
        with self._lock:
            state = self._states.get(assessment_id)
            if state is None:
                return
            existing = state.scanner_progress.get(scanner_id)
            if existing is None:
                return
            now = _now()
            duration = None
            if existing.start_time:
                try:
                    start = datetime.fromisoformat(existing.start_time)
                    duration = (datetime.fromisoformat(now) - start).total_seconds()
                except (ValueError, TypeError):
                    pass
            state.scanner_progress[scanner_id] = ScannerProgress(
                scanner_id=existing.scanner_id,
                name=existing.name,
                status=ScannerRunState.SUCCEEDED,
                start_time=existing.start_time,
                end_time=now,
                duration_seconds=round(duration, 1) if duration else None,
                findings_count=findings_count,
                warnings=warnings,
                port_specification=port_specification,
            )
            state.events.append(ExecutionEvent(
                event_type="scanner.completed",
                scanner_id=scanner_id,
                timestamp=now,
                message=f"Scanner {existing.name} completed — {findings_count} findings",
                progress_percent=_calc_progress(state),
            ))

    def fail_scanner(
        self,
        assessment_id: str,
        scanner_id: str,
        error: str,
    ) -> None:
        """Mark a scanner as failed."""
        with self._lock:
            state = self._states.get(assessment_id)
            if state is None:
                return
            existing = state.scanner_progress.get(scanner_id)
            if existing is None:
                return
            now = _now()
            state.scanner_progress[scanner_id] = ScannerProgress(
                scanner_id=existing.scanner_id,
                name=existing.name,
                status=ScannerRunState.FAILED,
                start_time=existing.start_time,
                end_time=now,
                error=error,
            )
            state.events.append(ExecutionEvent(
                event_type="scanner.failed",
                scanner_id=scanner_id,
                timestamp=now,
                message=f"Scanner {existing.name} failed: {error}",
                progress_percent=_calc_progress(state),
            ))

    def timeout_scanner(
        self,
        assessment_id: str,
        scanner_id: str,
        error: str,
    ) -> None:
        """Mark a scanner as timed out (its watchdog fired).

        Distinct from ``fail_scanner()`` (Phase 2A Correction 3 / FIX 1):
        before this, a timeout collapsed into the generic FAILED status
        and survived only as message text. A timeout is a specific,
        machine-readable outcome — the scanner did not error, it simply
        did not finish within its configured bound.
        """
        with self._lock:
            state = self._states.get(assessment_id)
            if state is None:
                return
            existing = state.scanner_progress.get(scanner_id)
            if existing is None:
                return
            now = _now()
            state.scanner_progress[scanner_id] = ScannerProgress(
                scanner_id=existing.scanner_id,
                name=existing.name,
                status=ScannerRunState.TIMED_OUT,
                start_time=existing.start_time,
                end_time=now,
                error=error,
            )
            state.events.append(ExecutionEvent(
                event_type="scanner.timed_out",
                scanner_id=scanner_id,
                timestamp=now,
                message=f"Scanner {existing.name} timed out: {error}",
                progress_percent=_calc_progress(state),
            ))

    def fail_execution(self, assessment_id: str, error: str) -> None:
        """Fail the entire execution."""
        with self._lock:
            state = self._states.get(assessment_id)
            if state is None:
                return
            now = _now()
            state.phase = ExecutionPhase.FAILED
            state.error_message = error
            state.completed_at = now
            state.events.append(ExecutionEvent(
                event_type="execution.failed",
                scanner_id=None,
                timestamp=now,
                message=f"Execution failed: {error}",
                progress_percent=100.0,
            ))

    def cancel_execution(self, assessment_id: str) -> bool:
        """Cancel a running execution.  Returns True if cancelled."""
        with self._lock:
            state = self._states.get(assessment_id)
            if state is None:
                return False
            if state.phase.is_terminal:
                return False
            if ExecutionPhase.CANCELLED not in _VALID_TRANSITIONS.get(state.phase, set()):
                return False
            now = _now()
            state.phase = ExecutionPhase.CANCELLED
            state.completed_at = now
            state.events.append(ExecutionEvent(
                event_type="execution.cancelled",
                scanner_id=None,
                timestamp=now,
                message="Execution cancelled by user",
                progress_percent=100.0,
            ))
            return True

    # ── Queries ──────────────────────────────────────────────────────────

    def get_state(self, assessment_id: str) -> AssessmentExecutionState | None:
        """Return the current execution state for an assessment."""
        with self._lock:
            state = self._states.get(assessment_id)
            if state is None:
                return None
            return AssessmentExecutionState(
                assessment_id=state.assessment_id,
                phase=state.phase,
                progress_percent=_calc_progress(state),
                scanner_progress=tuple(state.scanner_progress.values()),
                events=tuple(state.events),
                started_at=state.started_at,
                completed_at=state.completed_at,
                error_message=state.error_message,
            )

    def get_progress(self, assessment_id: str) -> float | None:
        """Return overall progress percentage, or None if not tracked."""
        with self._lock:
            state = self._states.get(assessment_id)
            if state is None:
                return None
            return _calc_progress(state)

    def get_events(self, assessment_id: str) -> tuple[ExecutionEvent, ...]:
        """Return ordered events for an assessment."""
        with self._lock:
            state = self._states.get(assessment_id)
            if state is None:
                return ()
            return tuple(state.events)

    def is_cancelled(self, assessment_id: str) -> bool:
        """Check if an execution has been cancelled."""
        with self._lock:
            state = self._states.get(assessment_id)
            if state is None:
                return False
            return state.phase == ExecutionPhase.CANCELLED

    def cleanup(self, assessment_id: str) -> None:
        """Remove execution state (e.g. after assessment deletion)."""
        with self._lock:
            self._states.pop(assessment_id, None)


@dataclass
class _InternalState:
    assessment_id: str
    phase: ExecutionPhase
    scanner_progress: dict[str, ScannerProgress]
    events: list[ExecutionEvent]
    started_at: str | None = None
    completed_at: str | None = None
    error_message: str | None = None


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _calc_progress(state: _InternalState) -> float:
    """Calculate overall progress from scanner completion + phase."""
    phase_progress = state.phase.progress_percent
    scanners = list(state.scanner_progress.values())
    if not scanners:
        return phase_progress
    completed = sum(1 for s in scanners if s.status.is_terminal)
    scanner_ratio = completed / len(scanners)
    if state.phase == ExecutionPhase.RUNNING_SCANNERS:
        return 5.0 + scanner_ratio * 80.0
    return phase_progress
