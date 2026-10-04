"""Private helpers that turn raw request primitives into domain value objects.

This is the one place the application translates *domain* construction errors
(``InvariantViolation``) into *application* input errors (``InputValidationError``).
Doing it here keeps every use case free of repetitive try/except and gives
callers a consistent, application-level error for bad input.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from kingsec.domain import (
    Assessment,
    AssessmentId,
    AuthorizationGrant,
    InvariantViolation,
    ScannerRunSummary,
    Target,
    TargetSpecification,
    TargetSpecificationType,
    TargetType,
)
from kingsec.domain.identifiers import AuthorizationGrantId
from kingsec.domain.pipeline import PipelineExecution
from kingsec.domain.schedule import ScanSchedule
from kingsec.shared.errors import KingSecError

from .errors import (
    ApplicationError,
    AssessmentNotFoundError,
    InputValidationError,
    MfaStepUpAuthenticationError,
    PipelineNotFoundError,
    ScheduleNotFoundError,
)
from .ports import PasswordHasher, UserRepository


def to_assessment_id(raw: str) -> AssessmentId:
    """Build an AssessmentId, or raise InputValidationError if malformed."""
    try:
        return AssessmentId(raw)
    except InvariantViolation as exc:
        raise InputValidationError(f"invalid assessment id: {exc}") from exc


def check_assessment_access(assessment: Assessment, requesting_user: str, is_admin: bool) -> None:
    """Raise AssessmentNotFoundError unless the caller owns this assessment or is Admin.

    Fails closed: an assessment with no recorded owner (created before
    ownership was tracked) is Admin-only, not open to everyone.
    """
    if is_admin:
        return
    if assessment.owner_id and assessment.owner_id == requesting_user:
        return
    raise AssessmentNotFoundError(str(assessment.id))


def check_schedule_access(schedule: ScanSchedule, requesting_user: str, is_admin: bool) -> None:
    """Raise ScheduleNotFoundError unless the caller owns this schedule or is Admin.

    Phase 70 / Finding KSEC-69-01: mirrors check_assessment_access()
    exactly - same fail-closed semantics (a schedule with no recorded
    owner is Admin-only, not open to everyone), and the same choice of
    exception, so a non-owner cannot distinguish "this schedule does not
    exist" from "this schedule exists but belongs to someone else" -
    both raise the identical ScheduleNotFoundError, which the web
    adapter already maps to a generic 404.
    """
    if is_admin:
        return
    if schedule.owner_user_id and schedule.owner_user_id == requesting_user:
        return
    raise ScheduleNotFoundError(f"schedule '{schedule.id}' not found")


def check_pipeline_access(execution: PipelineExecution, requesting_user: str, is_admin: bool) -> None:
    """Raise PipelineNotFoundError unless the caller owns this pipeline or is Admin.

    Phase 72 / Finding KSEC-71-01: mirrors check_schedule_access() exactly
    - same fail-closed semantics (a pipeline with no recorded owner is
    Admin-only, not open to everyone), and the same choice of exception,
    so a non-owner cannot distinguish "this pipeline does not exist" from
    "this pipeline exists but belongs to someone else" - both raise the
    identical PipelineNotFoundError, which the web adapter already maps
    to a generic 404.
    """
    if is_admin:
        return
    if execution.owner_user_id and execution.owner_user_id == requesting_user:
        return
    raise PipelineNotFoundError(f"Pipeline '{execution.pipeline_id}' not found")


def verify_step_up_password(users: UserRepository, hasher: PasswordHasher, user_id: str, password: str) -> None:
    """Raise MfaStepUpAuthenticationError unless ``password`` matches the
    user's current password hash.

    KSEC-73-03: shared step-up check for security-downgrading MFA
    operations (disable / recovery-code regenerate / rotate) - reuses
    the same UserRepository/PasswordHasher pair every other password
    verification in this application already uses, rather than a new
    parallel credential check.
    """
    user = users.find_by_id(user_id)
    if user is None or not hasher.verify(password, user.password_hash):
        raise MfaStepUpAuthenticationError("current password is incorrect")


def safe_failure_message(exc: BaseException) -> str:
    """The safe, user-facing text for an exception that failed an operation.

    KingSecError already separates rich internal detail (``message``) from
    safe user-facing text (``user_message``) - reuse that. ApplicationError
    (AssessmentNotFoundError, ExecutionPlanUnsatisfiedError, etc.) has no
    such split, but every subclass is a deliberately-authored, developer-
    controlled business-rule message, not a wrapped raw exception, so its
    str() is safe by construction. Anything else (subprocess, filesystem,
    network, or other unvetted exceptions) may carry paths, hostnames, or
    command lines the caller never validated as safe to show a user - those
    collapse to the generic default, the same fallback
    ExceptionHandlerRegistry already uses at the HTTP boundary.
    """
    if isinstance(exc, KingSecError):
        return exc.user_message
    if isinstance(exc, ApplicationError):
        return str(exc)
    return KingSecError.default_user_message


def scanner_stderr_excerpt(exc: BaseException) -> str | None:
    """The raw stderr tail captured in a scanner failure's context, if any
    (Phase 2B-c Priority 4 - recurring-class instance nine: a scanner's
    real failure reason was captured at raise time but dead-ended in an
    exception's context, never reaching the operator).

    Deliberately distinct from safe_failure_message() above: this is the
    scanner TOOL's own diagnostic output (already truncated to 500 chars
    at the point of capture - see e.g. ffuf.py's ScannerExecutionError
    raise sites), not free-form exception text, and is surfaced only in
    the Scanner Coverage section for the operator reviewing why a run
    failed - never folded into the generic safe_failure_message() used
    at the application error boundary.
    """
    if isinstance(exc, KingSecError):
        stderr = exc.context.get("stderr")
        if isinstance(stderr, str) and stderr:
            return stderr
    return None


def compose_all_scanners_failed_message(failed_scanners: Sequence[ScannerRunSummary]) -> str:
    """A safe, user-facing failure_reason for an assessment where every
    attempted scanner failed.

    Names and counts only - never a per-scanner ``skipped_reason``/``error``
    string. Those are recorded by ``engine.fail_scanner()`` from a raw
    ``str(exc)`` (see execution_routes.py's own sanitization for that sink)
    and have not been run through safe_failure_message()'s split, so
    composing them in here would reopen the same class of leak Phase 03
    closed for the other two .fail() call sites. Reusing that split isn't
    applicable to per-scanner text at all under this design - the fix is to
    never interpolate it, not to sanitize and interpolate it.
    """
    names = [s.name for s in failed_scanners]
    if len(names) == 1:
        return f"The configured scanner failed to complete: {names[0]}. No results are available for this assessment."
    return (
        f"All {len(names)} configured scanners failed to complete: "
        f"{', '.join(names)}. No results are available for this assessment."
    )


def _parse_target_type(raw: str) -> TargetType:
    """Parse a target-type string into the enum, or raise InputValidationError."""
    try:
        return TargetType(raw)
    except ValueError as exc:
        allowed = ", ".join(t.value for t in TargetType)
        raise InputValidationError(f"invalid target type {raw!r}; expected one of: {allowed}") from exc


def build_target(value: str, type_raw: str) -> Target:
    """Build a validated Target from raw primitives."""
    target_type = _parse_target_type(type_raw)
    try:
        return Target(value, target_type)
    except InvariantViolation as exc:
        raise InputValidationError(str(exc)) from exc


def _parse_target_specification_type(raw: str) -> TargetSpecificationType:
    """Parse a target-specification-type string, or raise InputValidationError."""
    try:
        return TargetSpecificationType(raw)
    except ValueError as exc:
        allowed = ", ".join(t.value for t in TargetSpecificationType)
        raise InputValidationError(f"invalid target specification type {raw!r}; expected one of: {allowed}") from exc


def build_target_specification(type_raw: str, value: str) -> TargetSpecification:
    """Build a validated TargetSpecification from raw primitives (Phase 4)."""
    spec_type = _parse_target_specification_type(type_raw)
    try:
        return TargetSpecification(type=spec_type, value=value)
    except InvariantViolation as exc:
        raise InputValidationError(str(exc)) from exc


def parse_utc_datetime(raw: str) -> datetime:
    """Parse an ISO-8601 timestamp, or raise InputValidationError.

    Phase 4: AuthorizationGrant.valid_from/valid_until require a
    timezone-aware datetime - a bare ValueError from a malformed string,
    or the domain's own InvariantViolation for a naive one, both collapse
    to the same application-level InputValidationError a caller expects.
    """
    try:
        moment = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise InputValidationError(f"invalid timestamp {raw!r}: {exc}") from exc
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise InputValidationError(f"timestamp {raw!r} must be timezone-aware (e.g. end with 'Z' or '+00:00')")
    return moment


def build_authorization_grant(
    *,
    grant_id: AuthorizationGrantId,
    authorized_by: str,
    authorizing_organization: str,
    target_specification: TargetSpecification,
    valid_from: datetime,
    valid_until: datetime,
    created_by: str,
) -> AuthorizationGrant:
    """Build a validated AuthorizationGrant from already-parsed primitives.

    Phase 4: the AuthorizationGrant constructor itself raises
    InvariantViolation for e.g. valid_until <= valid_from - translated
    here into InputValidationError, the same boundary every other
    build_*() helper in this module enforces, rather than letting the
    domain error escape CreateAuthorizationGrant.execute() uncaught.
    """
    try:
        return AuthorizationGrant(
            id=grant_id,
            authorized_by=authorized_by,
            authorizing_organization=authorizing_organization,
            target_specification=target_specification,
            valid_from=valid_from,
            valid_until=valid_until,
            created_by=created_by,
        )
    except InvariantViolation as exc:
        raise InputValidationError(str(exc)) from exc
