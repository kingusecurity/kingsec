"""Use case: submit a scheduled scan as a real, tracked, exactly-once assessment.

KSEC-98-01. This is the orchestrator Phase 97 recommended and Phase 98
implements: the scheduler's only assessment-related dependency, replacing
the inert ``JobServicePort.submit_scan()`` path (Phase 95) with the real,
already-wired ``CreateAssessment`` -> ``SubmitAssessment`` pipeline.

It owns exactly what a background poller cannot own itself:

    * the scheduler's own, non-human execution identity (no HTTP request,
      no authenticated user exists here - see SCHEDULER_SERVICE_USER_ID);
    * deriving a stable occurrence identity from the schedule being
      fulfilled;
    * atomically claiming that occurrence, so the same logical firing can
      never produce two independent real assessments no matter how many
      times a crash/retry/finalization-failure boundary is crossed
      (Phase 94/96's residual risk);
    * calling CreateAssessment then SubmitAssessment with that identity.

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
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.schedule_occurrence_repository import ScheduleOccurrenceRepositoryPort
from kingsec.application.schedule_occurrence import INITIAL_OCCURRENCE_KEY, OccurrenceStatus
from kingsec.application.submit_assessment import SubmitAssessment
from kingsec.application.use_cases.create_assessment import CreateAssessment
from kingsec.domain.audit import AuditAction, AuditEntry
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

    NO_ACTION_TAKEN covers two distinct-but-equally-safe cases: the
    occurrence was already fully SUBMITTED by an earlier call, or a
    concurrent caller currently holds the exclusive right to finish it
    (lost a try_begin_creation()/try_begin_submission() race). Both are
    "someone already has this, or will finish it - I must not act again",
    which is the only fact this caller needs to act on; a real scheduler
    instance can never actually observe the second case in production,
    since Phase 93's schedule-level try_claim() already ensures only one
    instance ever calls execute() for a given due schedule at a time - it
    is reachable only by calling this use case directly, as the Phase 98
    concurrency tests deliberately do.
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
        audit: AuditPublisher | None = None,
    ) -> None:
        self._occurrences = occurrences
        self._create_assessment = create_assessment
        self._submit_assessment = submit_assessment
        self._audit = audit

    def execute(self, schedule: ScanSchedule) -> SubmitScheduledAssessmentResult:
        occurrence_key = derive_occurrence_key(schedule)
        occurrence = self._occurrences.try_claim(str(schedule.id), occurrence_key)

        if occurrence.status in (
            OccurrenceStatus.SUBMITTED,
            OccurrenceStatus.CREATING,
            OccurrenceStatus.SUBMITTING,
        ):
            # SUBMITTED: fully done already. CREATING/SUBMITTING: a
            # concurrent caller currently holds the exclusive right to
            # finish this occurrence (Case D/E) - either way, this caller
            # must not act.
            return SubmitScheduledAssessmentResult(
                outcome=ScheduledAssessmentOutcome.NO_ACTION_TAKEN,
                occurrence_id=occurrence.id,
                assessment_id=occurrence.assessment_id,
            )

        assessment_id = occurrence.assessment_id
        current_version = occurrence.version

        if occurrence.status == OccurrenceStatus.CLAIMED:
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
