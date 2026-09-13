"""Use case: submit an assessment for background execution.

This is the async counterpart of ``StartAssessment``. Instead of running the
scan synchronously, it transitions the assessment to RUNNING and submits the
scan work to a ``JobRunner`` for background execution. The caller receives
immediate confirmation (HTTP 202) while the scan runs in a background thread.

The application layer does not know about threads, executors, or asyncio.
It submits a callable to the ``JobRunner`` port; the infrastructure decides
how to execute it.

Error handling
    If the background scan fails, the assessment is marked FAILED with a
    reason. The caller can poll ``GET /assessments/{id}`` to see the final
    state.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from kingsec.domain import AssessmentId, Finding, ScannerRunSummary
from kingsec.domain.audit import AuditAction, AuditEntry

from ._support import (
    check_assessment_access,
    compose_all_scanners_failed_message,
    safe_failure_message,
    to_assessment_id,
)
from .assessment_execution import AssessmentExecutionEngine, ExecutionPhase, ScannerPlanEntry
from .assessment_profiles import ExecutionPlanner, PlanScannerEntry
from .dto import SubmitAssessmentRequest, SubmitAssessmentResponse
from .errors import AssessmentConflictError, ExecutionPlanUnsatisfiedError
from .events import (
    EVENT_ASSESSMENT_COMPLETED,
    EVENT_ASSESSMENT_FAILED,
    EVENT_ASSESSMENT_RUNNING,
    AssessmentEvent,
)
from .ports import (
    AIPort,
    AssessmentRepository,
    AuditPublisher,
    EventPublisher,
    JobRunner,
    ScannerExecutor,
    ScannerPort,
)
from .ports.outbound.assessment_execution_repository import AssessmentExecutionRepositoryPort


class SubmitAssessment:
    """Validate an assessment and submit it for background scanning."""

    def __init__(
        self,
        assessments: AssessmentRepository,
        scanner: ScannerPort,
        job_runner: JobRunner,
        ai: AIPort | None = None,
        events: EventPublisher | None = None,
        audit: AuditPublisher | None = None,
        execution_engine: AssessmentExecutionEngine | None = None,
        planner: ExecutionPlanner | None = None,
        scanner_executor: ScannerExecutor | None = None,
        execution_ledger: AssessmentExecutionRepositoryPort | None = None,
    ) -> None:
        self._assessments = assessments
        self._scanner = scanner
        self._job_runner = job_runner
        self._ai = ai
        self._events = events
        self._audit = audit
        self._execution_engine = execution_engine
        self._planner = planner
        self._scanner_executor = scanner_executor
        # KSEC-102-01: the durable execution ledger, independent of
        # ThreadJobRunner memory / process lifetime - see
        # assessment_execution_ledger.py. Optional so every existing test
        # double that constructs SubmitAssessment directly (without a real
        # database-backed ledger) keeps behaving exactly as before; only the
        # composition-root-wired production instance gets ledger tracking.
        self._execution_ledger = execution_ledger

    def execute(self, request: SubmitAssessmentRequest) -> SubmitAssessmentResponse:
        assessment_id = to_assessment_id(request.assessment_id)
        assessment = self._assessments.get(assessment_id)
        check_assessment_access(assessment, request.requesting_user, request.is_admin)

        # The authorization gate: AUTHORIZED -> RUNNING.
        # Raises IllegalStateTransition if not authorized.
        assessment.start()
        self._assessments.save(assessment)

        # KSEC-102-01: create the durable REQUESTED execution record
        # synchronously, in this request thread, right after the assessment
        # itself is durably RUNNING and before the background job is even
        # submitted to ThreadJobRunner - "every assessment that enters the
        # real execution path has a durable execution record before
        # execution is attempted" (Phase 101/102 Step 14). Unlike the
        # best-effort event/audit publishing below, a failure here
        # propagates: this ledger is a correctness mechanism, not a side
        # channel, so it must never be silently swallowed.
        if self._execution_ledger is not None:
            self._execution_ledger.create_requested(str(assessment.id))

        self._publish_event(
            AssessmentEvent(
                event_type=EVENT_ASSESSMENT_RUNNING,
                assessment_id=str(assessment.id),
                state=assessment.status.value,
                message="Background scan started",
                owner_id=assessment.owner_id,
            )
        )

        self._publish_audit(
            AuditEntry(
                action=AuditAction.ASSESSMENT_SUBMITTED,
                resource_type="assessment",
                resource_id=str(assessment.id),
                success=True,
                user_id=request.requesting_user,
                username=request.requesting_username,
            )
        )

        # Submit background work. The closure captures the ports it needs.
        job_id = str(assessment.id)

        if self._execution_engine is not None:
            # Create the tracked execution state synchronously, in this
            # request thread, before the scan is even submitted to the
            # background job runner. The real scanner list isn't known
            # yet (it's computed inside the background job below via
            # planner.plan()/compatible_scanners()) so this starts empty
            # and _execute_scan() fills it in with set_scanner_plan()
            # once it knows. Without this synchronous placeholder, a
            # client polling GET .../execution/status right after this
            # call returns could race the background thread's startup
            # (thread-pool scheduling isn't instantaneous) and see a
            # false 404 for an assessment that is genuinely running.
            self._execution_engine.start_execution(job_id, {})

        background_fn = self._make_background_fn(
            assessment_id=assessment_id,
            assessments=self._assessments,
            scanner=self._scanner,
            ai=self._ai,
            events=self._events,
            execution_engine=self._execution_engine,
            planner=self._planner,
            scanner_executor=self._scanner_executor,
            execution_ledger=self._execution_ledger,
        )
        self._job_runner.submit(job_id, background_fn)

        return SubmitAssessmentResponse(
            assessment_id=str(assessment.id),
            status=assessment.status.value,
            job_id=job_id,
        )

    def _publish_event(self, event: AssessmentEvent) -> None:
        """Publish an event if a publisher is configured (best-effort)."""
        if self._events is None:
            return
        try:
            self._events.publish(event)
        except Exception as exc:
            logging.getLogger(__name__).warning("event publish failed (best-effort): %s", exc)

    def _publish_audit(self, entry: AuditEntry) -> None:
        """Publish an audit entry if a publisher is configured (best-effort)."""
        if self._audit is None:
            return
        try:
            self._audit.record(entry)
        except Exception as exc:
            logging.getLogger(__name__).warning("audit publish failed (best-effort): %s", exc)

    @staticmethod
    def _make_background_fn(
        *,
        assessment_id: AssessmentId,
        assessments: AssessmentRepository,
        scanner: ScannerPort,
        ai: AIPort | None,
        events: EventPublisher | None,
        execution_engine: AssessmentExecutionEngine | None,
        planner: ExecutionPlanner | None,
        scanner_executor: ScannerExecutor | None,
        execution_ledger: AssessmentExecutionRepositoryPort | None = None,
    ) -> Callable[[], None]:
        """Build a closure that runs the scan in the background."""

        def _run_scan() -> None:
            _execute_scan(
                assessment_id=assessment_id,
                assessments=assessments,
                scanner=scanner,
                ai=ai,
                events=events,
                execution_engine=execution_engine,
                planner=planner,
                scanner_executor=scanner_executor,
                execution_ledger=execution_ledger,
            )

        return _run_scan


def _execute_scan(
    *,
    assessment_id: AssessmentId,
    assessments: AssessmentRepository,
    scanner: ScannerPort,
    ai: AIPort | None,
    events: EventPublisher | None = None,
    execution_engine: AssessmentExecutionEngine | None = None,
    planner: ExecutionPlanner | None = None,
    scanner_executor: ScannerExecutor | None = None,
    execution_ledger: AssessmentExecutionRepositoryPort | None = None,
) -> None:
    """Run the scan and complete the assessment. Called from a background thread.

    Each call gets a fresh assessment object from the repository so there is
    no shared mutable state between threads.
    """
    assessment = assessments.get(assessment_id)
    tracking_id = str(assessment_id)

    # KSEC-102-01: atomically claim the durable execution record and commit
    # RUNNING BEFORE the scanner is ever invoked (Step 16) - not after,
    # which would recreate the exact "did it start?" ambiguity Phase 101
    # identified. A losing claimant (only reachable today via a direct,
    # repository-level concurrency test - ThreadJobRunner's own
    # already-running guard and Assessment's own single-entry RUNNING
    # transition mean a real second concurrent caller cannot currently
    # arise through the production call graph) must stop here and never
    # reach the scanner.
    execution_id: str | None = None
    running_version: int | None = None
    if execution_ledger is not None:
        execution = execution_ledger.get_by_assessment_id(tracking_id)
        if execution is None:
            logging.getLogger(__name__).error(
                "no durable execution record found for assessment %s - proceeding without ledger tracking",
                tracking_id,
            )
        else:
            execution_id = execution.id
            claimed_version = execution_ledger.try_claim(execution.id, execution.version)
            if claimed_version is None:
                logging.getLogger(__name__).warning(
                    "lost the execution claim race for assessment %s - not invoking the scanner", tracking_id
                )
                return
            running_version = execution_ledger.try_mark_running(execution.id, claimed_version)
            if running_version is None:
                logging.getLogger(__name__).warning(
                    "lost the RUNNING transition race for assessment %s - not invoking the scanner", tracking_id
                )
                return

    try:
        # Which scanners are allowed to run, and what the profile's plan
        # already ruled out before execution even starts.
        #
        # Phase 2A Correction 2b: the planner now decides EVERY scanner in
        # the profile - each is either selected or carries one of the
        # SKIPPED_* terminal states, in the SAME unified vocabulary the
        # execution engine tracks. There is no separate "preplanned skips"
        # bucket bolted on after the fact anymore: set_scanner_plan()
        # seeds every scanner (selected -> PENDING, skipped -> its
        # terminal state immediately) in one call, so a scanner that will
        # never be dispatched is never left "pending" even transiently -
        # this is what makes the Run #4 reference-case defect structurally
        # impossible, not merely unlikely.
        scanner_ids: tuple[str, ...] | None = None

        if assessment.profile_id is not None and planner is not None:
            # Server-side re-validation: re-plan now, at execution time,
            # rather than trusting whatever the client saw at an earlier
            # /plan preview - scanner availability can change in the async
            # gap between preview and this background run.
            plan = planner.plan(assessment.profile_id, assessment.target.value, assessment.target.type)
            if not plan.can_proceed:
                reason = "; ".join(plan.warnings) or (
                    f"profile {assessment.profile_id!r} cannot proceed: "
                    "a required scanner is unavailable"
                )
                raise ExecutionPlanUnsatisfiedError(reason)

            scanner_ids = tuple(e.scanner_id for e in plan.selected_scanners)
            all_plan_entries: tuple[PlanScannerEntry, ...] = (
                *plan.selected_scanners,
                *plan.skipped_scanners,
                *plan.unavailable_scanners,
            )
            if execution_engine is not None:
                execution_engine.set_scanner_plan(
                    tracking_id,
                    tuple(
                        ScannerPlanEntry(
                            scanner_id=e.scanner_id,
                            name=e.name,
                            selected=e.selected,
                            skip_state=e.skip_state,
                            skip_reason=e.reason or None,
                        )
                        for e in all_plan_entries
                    ),
                )
        elif execution_engine is not None:
            # No profile: today's exact "run everything compatible"
            # behavior - every compatible scanner is selected, none skipped.
            selected_names = scanner.compatible_scanners(assessment.target)
            execution_engine.set_scanner_plan(
                tracking_id,
                tuple(
                    ScannerPlanEntry(scanner_id=sid, name=name, selected=True)
                    for sid, name in selected_names.items()
                ),
            )

        if execution_engine is not None:
            execution_engine.transition_phase(tracking_id, ExecutionPhase.RUNNING_SCANNERS)

        if scanner_executor is not None:
            # The richer lifecycle port: reports real per-scanner start/
            # completion/failure to the execution engine as it runs.
            results = scanner_executor.execute_all(
                assessment.target,
                scanner_ids=scanner_ids,
                execution_engine=execution_engine,
                tracking_id=tracking_id,
            )
            findings: list[Finding] = [f for result in results for f in result.findings]
        elif scanner_ids is not None:
            findings = list(scanner.scan(assessment.target, scanner_ids=scanner_ids))
        else:
            findings = list(scanner.scan(assessment.target))

        for finding in findings:
            _enrich(finding, ai)
            assessment.record_finding(finding)

        if execution_engine is not None:
            execution_engine.transition_phase(tracking_id, ExecutionPhase.CORRELATING)
            execution_engine.transition_phase(tracking_id, ExecutionPhase.REPORTING)

        # Populated only when BOTH execution_engine and scanner_executor are
        # set (Phase 06 §2.1's original invariant, restored here): only the
        # scanner_executor path reports real per-scanner start/complete/
        # fail/timeout events to the engine as scanning happens. The plain
        # scanner.scan() fallback (scanner_executor is None) never advances
        # whatever set_scanner_plan() seeded, so reading execution_engine's
        # state there would see permanently-stale PENDING entries and
        # wrongly conclude "zero scanners succeeded" for a scan that
        # genuinely completed - exactly the false-FAILED regression this
        # gate exists to prevent.
        non_succeeded: tuple[ScannerRunSummary, ...] = ()
        succeeded_count = 0
        total_count = 0
        if execution_engine is not None and scanner_executor is not None:
            state = execution_engine.get_state(tracking_id)
            progress = state.scanner_progress if state is not None else ()

            # Phase 2A Correction 2d: the planner/orchestrator invariant,
            # enforced here, loudly, not merely assumed. Every scanner the
            # planner marked selected must now be in a TERMINAL state - if
            # scanner_ids is set and any of them is still PENDING/RUNNING,
            # execute_all() silently failed to process something it was
            # given, which is exactly the class of defect this phase
            # exists to make structurally impossible. Fail loudly rather
            # than let it slip through as an ordinary "pending forever".
            if scanner_ids is not None:
                by_id = {p.scanner_id: p for p in progress}
                non_terminal = [
                    sid for sid in scanner_ids
                    if sid not in by_id or not by_id[sid].status.is_terminal
                ]
                if non_terminal:
                    raise RuntimeError(
                        "planner/orchestrator invariant violated: scanner(s) "
                        f"{non_terminal!r} were selected by the plan but did not "
                        "reach a terminal state"
                    )

            all_summaries = tuple(
                ScannerRunSummary(
                    scanner_id=p.scanner_id,
                    name=p.name,
                    status=p.status,
                    findings_count=p.findings_count,
                    # skipped_reason covers every pre-execution SKIPPED_*
                    # state; error covers FAILED/TIMED_OUT - a scanner's
                    # real outcome reason lives in whichever of the two
                    # its terminal status actually set.
                    skipped_reason=p.skipped_reason or p.error,
                    # Phase 2B Task 2: a scanner can succeed but still
                    # carry a warning (e.g. nmap's URL-derived port
                    # overriding an operator-configured -p) - this is what
                    # makes that fact survive into the persisted report
                    # instead of dead-ending in the in-memory execution
                    # state once the assessment completes.
                    warnings=p.warnings,
                    # Task 4: survives to the persisted report so the
                    # Limitations section can state real port coverage.
                    port_specification=p.port_specification,
                )
                for p in progress
            )
            assessment.record_scanner_summary(all_summaries)

            total_count = len(all_summaries)
            succeeded_count = sum(1 for s in all_summaries if s.status.is_success)
            non_succeeded = tuple(s for s in all_summaries if not s.status.is_success)

        # Phase 2A FIX 3 - honest assessment status:
        #   COMPLETED            only when every scheduled scanner SUCCEEDED
        #   COMPLETED_WITH_GAPS  any scanner skipped, failed, or timed out
        #   FAILED               zero scanners succeeded
        # A partial run must never be labelled COMPLETED, no exceptions -
        # this is what makes the Run #4 reference case ("88.0/100 - Sound"
        # with 6 of 9 scanners never run) structurally impossible.
        assessment_failed = total_count > 0 and succeeded_count == 0
        if assessment_failed:
            assessment.fail(compose_all_scanners_failed_message(non_succeeded))
        elif non_succeeded:
            assessment.complete_with_gaps()
        else:
            assessment.complete()
        assessments.save(assessment)

        # KSEC-102-01: the ledger's terminal transition happens strictly
        # AFTER assessments.save() above has durably committed the
        # Assessment's own terminal status - that save() is the actual
        # durable fact proving completion/failure, not merely "the scanner
        # function returned" (Step 17/18). A lost transition here (None/
        # False) means a concurrent process already reconciled or
        # transitioned this record - never re-raised, since the Assessment
        # itself is already correctly terminal regardless.
        #
        # COMPLETED_WITH_GAPS maps to ledger SUCCEEDED, not FAILED: the
        # execution process itself ran to a genuine terminal conclusion -
        # partial coverage is a business-level fact the Assessment's own
        # status already carries, not a process-level failure the ledger
        # needs to separately represent.
        if execution_ledger is not None and execution_id is not None and running_version is not None:
            if assessment_failed:
                execution_ledger.try_mark_failed(execution_id, running_version)
            else:
                execution_ledger.try_mark_succeeded(execution_id, running_version)

        if execution_engine is not None:
            execution_engine.transition_phase(tracking_id, ExecutionPhase.COMPLETED)

        _publish_event(
            events,
            AssessmentEvent(
                event_type=EVENT_ASSESSMENT_COMPLETED,
                assessment_id=str(assessment.id),
                state=assessment.status.value,
                message=f"Scan completed with {len(assessment.findings)} findings",
                severity_counts=_severity_counts(assessment),
                owner_id=assessment.owner_id,
            ),
        )

    except Exception as exc:
        if execution_engine is not None:
            execution_engine.fail_execution(tracking_id, str(exc))

        if isinstance(exc, AssessmentConflictError):
            # KSEC-109-01/KSEC-110-01 observability gap (Phase 111): the
            # scan's own genuine outcome could not be durably recorded
            # because a concurrent lifecycle change
            # (CancelAssessment/DeleteAssessment) already won and altered
            # the durable state first - never a stale overwrite
            # (persist_assessment() itself prevents that), but silently
            # invisible to an operator unless logged distinctly from any
            # other, truly unexpected failure. The in-memory ``assessment``
            # may already be COMPLETED here (if the scan itself succeeded
            # and only its own save() conflicted) - attempting
            # ``.fail()`` on it would just raise a second, unrelated-
            # looking IllegalStateTransition, so the recovery write is
            # skipped entirely: there is nothing safe left to persist.
            # No finding content or exception detail is logged - ids and
            # a fixed reason only.
            _log_scan_result_discarded(tracking_id, execution_id)
            return

        try:
            assessment.fail(safe_failure_message(exc))
            assessments.save(assessment)

            # KSEC-102-01: same evidence-after-the-fact ordering as the
            # success path - only after the Assessment itself is durably
            # FAILED. If running_version is still None, the exception was
            # raised before RUNNING was ever committed (e.g. the claim
            # itself failed) - there is no valid version to transition
            # from, so the ledger is left at its current state rather than
            # guessed at.
            if execution_ledger is not None and execution_id is not None and running_version is not None:
                execution_ledger.try_mark_failed(execution_id, running_version)

            _publish_event(
                events,
                AssessmentEvent(
                    event_type=EVENT_ASSESSMENT_FAILED,
                    assessment_id=str(assessment.id),
                    state=assessment.status.value,
                    message=f"Scan failed: {exc}",
                    owner_id=assessment.owner_id,
                ),
            )
        except AssessmentConflictError:
            # Same event as above (Phase 111) - this time the conflict was
            # only discovered at the recovery-write point itself (the
            # original failure was something else; a concurrent
            # Cancel/Delete won in the meantime).
            _log_scan_result_discarded(tracking_id, execution_id)
        except Exception as exc:
            logging.getLogger(__name__).warning("scan recovery failed (best-effort): %s", exc)


def _log_scan_result_discarded(assessment_id: str, execution_id: str | None) -> None:
    """Phase 111 (KSEC-109-01/KSEC-110-01 observability gap): a single,
    named, structured WARNING event for the one specific case where a
    scan's real outcome could not be durably recorded because a
    concurrent Cancel/Delete already won. Deliberately just visibility -
    no retry, no lease, no change to any concurrency semantics. Carries
    only ids and a fixed reason string, never finding content or raw
    exception text."""
    logging.getLogger(__name__).warning(
        "scan_result_discarded_on_concurrent_lifecycle_change",
        extra={
            "event": "scan_result_discarded_on_concurrent_lifecycle_change",
            "assessment_id": assessment_id,
            "execution_id": execution_id,
            "reason": "a concurrent Cancel/Delete already changed this assessment's "
            "durable state before the scan's own outcome could be recorded",
        },
    )


def _enrich(finding: Finding, ai: AIPort | None) -> None:
    """Attach an AI recommendation if available (best-effort)."""
    if ai is None:
        return
    try:
        recommendation = ai.recommend(finding)
        finding.add_recommendation(recommendation)
    except Exception as exc:
        logging.getLogger(__name__).warning("AI enrichment failed (best-effort): %s", exc)
        return


def _publish_event(events: EventPublisher | None, event: AssessmentEvent) -> None:
    """Publish an event if a publisher is configured (best-effort)."""
    if events is None:
        return
    try:
        events.publish(event)
    except Exception as exc:
        logging.getLogger(__name__).warning("event publish failed (best-effort): %s", exc)


def _severity_counts(assessment: object) -> dict[str, int] | None:
    """Build a severity count dict from the assessment's findings."""
    from kingsec.domain import Assessment as AssessmentType

    if not isinstance(assessment, AssessmentType):
        return None
    counts: dict[str, int] = {}
    for finding in assessment.findings:
        label = finding.severity.label
        counts[label] = counts.get(label, 0) + 1
    return counts if counts else None
