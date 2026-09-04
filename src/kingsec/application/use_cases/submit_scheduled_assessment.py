"""Use case: submit a scheduled scan as a real, tracked assessment, with
best-effort, evidence-gated crash recovery for CREATING.

KSEC-98-01/KSEC-100-01. This is the orchestrator Phase 97 recommended and
Phase 98 implements: the scheduler's only assessment-related dependency,
replacing the inert ``JobServicePort.submit_scan()`` path (Phase 95) with
the real, already-wired ``CreateAssessment`` -> ``SubmitAssessment``
pipeline.

It owns exactly what a background poller cannot own itself:

    * the scheduler's own, non-human execution identity (no HTTP request,
      no authenticated user exists here - see SCHEDULER_SERVICE_USER_ID);
    * deriving a stable occurrence identity from the schedule being
      fulfilled;
    * atomically claiming that occurrence, so at most one real assessment
      is ever produced per occurrence no matter how many times a
      crash/retry/finalization-failure boundary is crossed (Phase
      94/96's residual risk);
    * calling CreateAssessment then SubmitAssessment with that identity;
    * (KSEC-100-01) recovering a CREATING occurrence left stuck by an
      unclean process termination, but ONLY when a durable, linked
      assessment PROVES CreateAssessment already committed - never by
      guessing via a timeout (Phase 99 proved a blind timeout-based reset
      can duplicate a real assessment).

Property this module actually provides: **at-most-one real assessment per
occurrence** (proven under both ordinary exceptions and real, unclean
process termination - Phase 98/99). It does NOT provide durable
exactly-once EXECUTION - SubmitAssessment hands the actual scan to an
in-memory ThreadJobRunner with no durable ledger, so whether a scan that
reached RUNNING actually executed is unknowable from this module alone
(Phase 99, Crash D). SUBMITTING is therefore never automatically
recovered here - see the SUBMITTING branch in ``execute()``.

It deliberately does NOT contain assessment creation/authorization logic
(that stays in CreateAssessment) or occurrence SQL (that stays in
ScheduleOccurrenceRepositoryPort's implementation) - this module only
sequences calls to those and interprets their results.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from enum import StrEnum

from kingsec.application.dto import CreateAssessmentRequest, SubmitAssessmentRequest
from kingsec.application.errors import ScheduledOccurrenceUnresolvedError
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.schedule_occurrence_repository import ScheduleOccurrenceRepositoryPort
from kingsec.application.ports.repositories import AssessmentRepository
from kingsec.application.schedule_occurrence import INITIAL_OCCURRENCE_KEY, OccurrenceStatus
from kingsec.application.submit_assessment import SubmitAssessment
from kingsec.application.use_cases.create_assessment import CreateAssessment
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.enums import AssessmentStatus
from kingsec.domain.schedule import ScanSchedule


def _detect_target_type(target: str) -> str:
    """Best-effort target-type detection for a schedule's plain target string.

    KSEC-98-01: ScanSchedule (and its dead-end predecessor, ScanJob) never
    recorded a target type - only a bare string - because neither
    JobServicePort.submit_scan() nor anything downstream of it needed one.
    CreateAssessment does require one (Target._validate_format() enforces
    that the value matches the declared type). Adding a target_type field
    to ScanSchedule/CreateScheduleRequest would be a schedule-domain schema
    change well beyond this phase's scope (identity + exactly-once); this
    detector reuses the exact same parsing rules Target itself validates
    against, so the type it picks is guaranteed to match the format
    Target._validate_format() will independently re-check - it cannot
    produce a type/format mismatch that CreateAssessment would then reject.
    """
    if target.startswith(("http://", "https://")):
        return "url"
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return "network"
        except ValueError:
            pass
    else:
        try:
            ipaddress.ip_address(target)
            return "ip_address"
        except ValueError:
            pass
    return "hostname"

# KSEC-98-01: the scheduler's dedicated, non-human execution identity
# (Phase 97, Option B - "scheduler service account"). A reserved, fixed
# value, never a real user_id - CreateAssessment sets Assessment.owner_id
# to this value, and SubmitAssessment's requesting_user is the SAME value,
# so check_assessment_access()'s ordinary ownership rule
# (assessment.owner_id == requesting_user) is satisfied *without*
# is_admin=True. This is the entire authorization mechanism: the scheduler
# identity can only ever match assessments it created under this exact
# owner_id, so it structurally cannot access any pre-existing, human-owned
# assessment - there is no separate permission check to bypass or misuse.
SCHEDULER_SERVICE_USER_ID = "scheduler-service"
SCHEDULER_SERVICE_USERNAME = "scheduler-service"


class ScheduledAssessmentOutcome(StrEnum):
    """Both members are non-error, safe-to-finalize outcomes - the
    scheduler proceeds to advance the schedule's next_run in either case.
    Only an exception (propagated, never swallowed here) means "do not
    finalize" - matching InProcessScheduler's existing behavior exactly.
    KSEC-100-01 relies on this: a stuck/ambiguous occurrence now raises
    ScheduledOccurrenceUnresolvedError instead of ever reaching either
    member below, so InProcessScheduler's existing exception handling
    (unchanged) is what actually prevents next_run from silently
    advancing over an abandoned occurrence.

    NO_ACTION_TAKEN covers three distinct-but-equally-safe cases: the
    occurrence was already fully SUBMITTED by an earlier call; a
    concurrent caller currently holds the exclusive right to finish it
    (lost a try_begin_creation()/try_begin_submission() race, a live
    collision in this exact instant - a real scheduler instance can never
    actually observe this in production, since Phase 93's schedule-level
    try_claim() already ensures only one instance ever calls execute()
    for a given due schedule at a time - it is reachable only by calling
    this use case directly, as the concurrency tests deliberately do); or
    a CREATING occurrence was just recovered here and the resulting
    ASSESSMENT_CREATED write raced a concurrent finisher (same harmless
    "both write the identical result" case). All three mean "someone
    already has this, or will finish it - I must not act again."
    """

    SUBMITTED = "SUBMITTED"
    NO_ACTION_TAKEN = "NO_ACTION_TAKEN"


@dataclass(frozen=True)
class SubmitScheduledAssessmentResult:
    outcome: ScheduledAssessmentOutcome
    occurrence_id: str
    assessment_id: str | None


def derive_occurrence_key(schedule: ScanSchedule) -> str:
    """The exact next_run value being fulfilled, reused byte-for-byte as
    the occurrence key.

    Deliberately NOT re-parsed/re-formatted: next_run is already a
    canonical, UTC, tzinfo-stripped ISO-8601 string
    (InProcessScheduler.calculate_next_run()) - copying it verbatim
    guarantees the same logical occurrence always produces the same key,
    with no risk of a re-serialization producing a different string for an
    equivalent instant.

    A schedule whose next_run is still None - either its very first firing
    (ScanSchedule.is_due()) or a ONE_TIME schedule, whose next_run never
    advances past None - always maps to the same sentinel key, so a
    ONE_TIME schedule that stays "due" forever only ever claims ONE
    occurrence: every poll after the first successful run finds it already
    SUBMITTED and does nothing further.
    """
    return schedule.next_run if schedule.next_run is not None else INITIAL_OCCURRENCE_KEY


class SubmitScheduledAssessment:
    """Establish scheduler identity, claim the occurrence exactly once,
    then create and submit the real assessment.
    """

    def __init__(
        self,
        occurrences: ScheduleOccurrenceRepositoryPort,
        create_assessment: CreateAssessment,
        submit_assessment: SubmitAssessment,
        assessments: AssessmentRepository,
        audit: AuditPublisher | None = None,
    ) -> None:
        self._occurrences = occurrences
        self._create_assessment = create_assessment
        self._submit_assessment = submit_assessment
        self._assessments = assessments
        self._audit = audit

    def execute(self, schedule: ScanSchedule) -> SubmitScheduledAssessmentResult:
        occurrence_key = derive_occurrence_key(schedule)
        occurrence = self._occurrences.try_claim(str(schedule.id), occurrence_key)

        if occurrence.status == OccurrenceStatus.SUBMITTED:
            return SubmitScheduledAssessmentResult(
                outcome=ScheduledAssessmentOutcome.NO_ACTION_TAKEN,
                occurrence_id=occurrence.id,
                assessment_id=occurrence.assessment_id,
            )

        if occurrence.status == OccurrenceStatus.SUBMITTING:
            # KSEC-100-01: deliberately NEVER auto-recovered. The linked
            # assessment may already be RUNNING via SubmitAssessment's
            # synchronous save(), but whether ThreadJobRunner's in-memory
            # background work actually executed before an unclean
            # termination is unknowable from durable state alone (Phase
            # 99, Crash D) - resuming or resubmitting here could duplicate
            # a real scan. This is explicitly out of scope for automatic
            # recovery; see the module docstring.
            self._publish_unresolved_audit(
                schedule,
                occurrence.id,
                occurrence_key,
                occurrence.assessment_id,
                "occurrence is stuck in SUBMITTING - cannot safely determine whether "
                "the scan already executed without a durable execution ledger",
            )
            raise ScheduledOccurrenceUnresolvedError(
                f"occurrence {occurrence.id} is stuck in SUBMITTING and cannot be safely "
                "recovered automatically (no durable execution ledger exists)"
            )

        assessment_id = occurrence.assessment_id
        current_version = occurrence.version

        if occurrence.status == OccurrenceStatus.CREATING:
            # KSEC-100-01: this occurrence claims CreateAssessment might
            # still be in flight - it could be a live, currently-executing
            # call (indistinguishable from a crashed one without a
            # liveness signal, Phase 99 Step 6) or the durable trace of a
            # crash. Recovery proceeds ONLY when a linked assessment
            # PROVES CreateAssessment already committed - it never calls
            # CreateAssessment again itself, and never guesses via a
            # timeout (Phase 99 proved that is unsafe).
            linked = self._assessments.find_by_schedule_occurrence_id(occurrence.id)
            if len(linked) == 1 and linked[0].status == AssessmentStatus.AUTHORIZED:
                recovered_id = str(linked[0].id)
                recovered = self._occurrences.mark_assessment_created(
                    occurrence.id, occurrence.version, recovered_id
                )
                if not recovered:
                    # The live creator finished normally (or a concurrent
                    # recovery attempt won) between our read and this
                    # write - both write the IDENTICAL resulting state
                    # (ASSESSMENT_CREATED, same assessment_id, since there
                    # is only one), so losing this race is harmless.
                    return SubmitScheduledAssessmentResult(
                        outcome=ScheduledAssessmentOutcome.NO_ACTION_TAKEN,
                        occurrence_id=occurrence.id,
                        assessment_id=recovered_id,
                    )
                assessment_id = recovered_id
                current_version = occurrence.version + 1
                # Falls through to the submission logic below, exactly as
                # if this occurrence had naturally reached
                # ASSESSMENT_CREATED.
            elif not linked:
                self._publish_unresolved_audit(
                    schedule,
                    occurrence.id,
                    occurrence_key,
                    None,
                    "occurrence is stuck in CREATING with no linked assessment - cannot "
                    "distinguish a live in-flight creation from a crashed one without a "
                    "liveness mechanism",
                )
                raise ScheduledOccurrenceUnresolvedError(
                    f"occurrence {occurrence.id} is stuck in CREATING with no linked "
                    "assessment - cannot be safely recovered automatically"
                )
            else:
                # Either more than one linked assessment (corruption -
                # never silently pick one) or exactly one with an
                # unexpected status (RUNNING/COMPLETED/FAILED/CANCELLED -
                # something progressed further than this occurrence
                # record shows, which is internally inconsistent and must
                # not be guessed at).
                self._publish_unresolved_audit(
                    schedule,
                    occurrence.id,
                    occurrence_key,
                    None,
                    f"ambiguous recovery state: {len(linked)} linked assessment(s), "
                    f"statuses={[a.status.value for a in linked]}",
                )
                raise ScheduledOccurrenceUnresolvedError(
                    f"occurrence {occurrence.id} has an ambiguous recovery state "
                    f"({len(linked)} linked assessments) - operator review required"
                )

        elif occurrence.status == OccurrenceStatus.CLAIMED:
            locked_version = self._occurrences.try_begin_creation(occurrence.id, current_version)
            if locked_version is None:
                # Lost the race to a concurrent claimant. Nothing was
                # lost: the occurrence row still exists and the winner (or
                # a later poll cycle) carries it forward safely.
                return SubmitScheduledAssessmentResult(
                    outcome=ScheduledAssessmentOutcome.NO_ACTION_TAKEN,
                    occurrence_id=occurrence.id,
                    assessment_id=None,
                )

            try:
                create_result = self._create_assessment.execute(
                    CreateAssessmentRequest(
                        target_value=schedule.target,
                        target_type=_detect_target_type(schedule.target),
                        authorized_by=schedule.owner_user_id,
                        scope=schedule.name,
                        owner_id=SCHEDULER_SERVICE_USER_ID,
                        requesting_username=SCHEDULER_SERVICE_USERNAME,
                        schedule_occurrence_id=occurrence.id,
                    )
                )
            except Exception:
                # Case A: revert CREATING -> CLAIMED so a later call can
                # safely retry from scratch - no assessment was ever
                # created, so no duplicate risk exists on retry.
                self._occurrences.revert_to_claimed(occurrence.id, locked_version)
                raise

            assessment_id = create_result.assessment_id
            self._occurrences.mark_assessment_created(occurrence.id, locked_version, assessment_id)
            # mark_assessment_created's own conditional UPDATE bumped the
            # version by exactly one more, from locked_version - this call
            # exclusively held that version, so the bump is guaranteed.
            current_version = locked_version + 1

        locked_version = self._occurrences.try_begin_submission(occurrence.id, current_version)
        if locked_version is None:
            return SubmitScheduledAssessmentResult(
                outcome=ScheduledAssessmentOutcome.NO_ACTION_TAKEN,
                occurrence_id=occurrence.id,
                assessment_id=assessment_id,
            )

        if assessment_id is None:  # pragma: no cover - invariant guard, not a reachable branch
            raise RuntimeError(f"occurrence {occurrence.id} reached submission with no assessment_id")

        try:
            self._submit_assessment.execute(
                SubmitAssessmentRequest(
                    assessment_id=assessment_id,
                    requesting_user=SCHEDULER_SERVICE_USER_ID,
                    requesting_username=SCHEDULER_SERVICE_USERNAME,
                    is_admin=False,
                )
            )
        except Exception:
            # Case B: revert SUBMITTING -> ASSESSMENT_CREATED so a later
            # call resumes submission on the SAME assessment, never
            # calling CreateAssessment again.
            self._occurrences.revert_to_assessment_created(occurrence.id, locked_version)
            raise

        self._occurrences.mark_submitted(occurrence.id, locked_version)

        self._publish_audit(schedule, occurrence.id, occurrence_key, assessment_id)

        return SubmitScheduledAssessmentResult(
            outcome=ScheduledAssessmentOutcome.SUBMITTED,
            occurrence_id=occurrence.id,
            assessment_id=assessment_id,
        )

    def _publish_audit(self, schedule: ScanSchedule, occurrence_id: str, occurrence_key: str, assessment_id: str) -> None:
        """Best-effort, additive audit entry answering WHO executed this /
        WHICH schedule / WHICH occurrence / WHO owns the schedule -
        without modifying CreateAssessment or SubmitAssessment's own,
        unrelated audit entries at all (Phase 98 Section 11: the smallest
        necessary extension, not a repair of the broader, separately-known
        correlation-id gap).
        """
        if self._audit is None:
            return
        try:
            self._audit.record(
                AuditEntry(
                    action=AuditAction.SCHEDULE_TRIGGERED,
                    resource_type="schedule",
                    resource_id=str(schedule.id),
                    user_id=SCHEDULER_SERVICE_USER_ID,
                    username=SCHEDULER_SERVICE_USERNAME,
                    metadata={
                        "schedule_id": str(schedule.id),
                        "schedule_owner": schedule.owner_user_id,
                        "occurrence_id": occurrence_id,
                        "occurrence_key": occurrence_key,
                        "assessment_id": assessment_id,
                    },
                )
            )
        except Exception as exc:
            logging.getLogger(__name__).warning("audit publish failed (best-effort): %s", exc)

    def _publish_unresolved_audit(
        self,
        schedule: ScanSchedule,
        occurrence_id: str,
        occurrence_key: str,
        assessment_id: str | None,
        reason: str,
    ) -> None:
        """Best-effort, additive audit entry AND structured log for an
        occurrence that could not be safely resolved (KSEC-100-01, Step 14
        operator visibility) - the smallest mechanism already consistent
        with this module's own established best-effort audit pattern,
        plus a log line so an operator does not need an audit-log query to
        notice. Fired BEFORE raising ScheduledOccurrenceUnresolvedError,
        so it is recorded even though the caller (InProcessScheduler)
        never sees a normal return value for this call.
        """
        logging.getLogger(__name__).warning(
            "scheduled occurrence unresolved: schedule_id=%s occurrence_id=%s reason=%s",
            schedule.id,
            occurrence_id,
            reason,
        )
        if self._audit is None:
            return
        try:
            self._audit.record(
                AuditEntry(
                    action=AuditAction.SCHEDULE_OCCURRENCE_UNRESOLVED,
                    resource_type="schedule",
                    resource_id=str(schedule.id),
                    success=False,
                    reason=reason,
                    user_id=SCHEDULER_SERVICE_USER_ID,
                    username=SCHEDULER_SERVICE_USERNAME,
                    metadata={
                        "schedule_id": str(schedule.id),
                        "schedule_owner": schedule.owner_user_id,
                        "occurrence_id": occurrence_id,
                        "occurrence_key": occurrence_key,
                        "assessment_id": assessment_id,
                    },
                )
            )
        except Exception as exc:
            logging.getLogger(__name__).warning("audit publish failed (best-effort): %s", exc)
