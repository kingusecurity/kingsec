"""Use case: resolve assessments orphaned by a process crash, at startup.

Phase 2A FIX 9. ``SubmitAssessment``'s background execution only persists
``Assessment.scanner_summary`` and transitions the assessment to a terminal
status ONCE, at the very end of a successful run (or in its own exception
handler on a caught failure) - see ``submit_assessment.py``. If the process
itself is killed mid-execution (crash, forced restart, OOM), neither of
those ever runs: the assessment is left durably stuck at RUNNING forever,
and whatever ``scanner_summary`` it carries predates this interrupted
attempt entirely (it is never safe to reason about "which scanners must
have run" from it).

This is a different situation from ``ReconcileAssessmentExecution``
(KSEC-105-01): that use case is evidence-gated and explicitly refuses to
act unless the Assessment ITSELF has already reached a terminal status -
exactly the case this module exists to handle is the one that use case
deliberately will not touch. This module is not human-triggered and not
evidence-gated in that sense; it runs once, automatically, at application
startup, before any new work is submitted - which is itself the evidence
that nothing it finds RUNNING can still legitimately be executing.

The interrupted outcome is recorded as FAILED, never COMPLETED_WITH_GAPS:
a crash is a genuinely indeterminate, interrupted outcome (we have no
reliable record of what ran this attempt), not a measured partial result.
"""

from __future__ import annotations

import logging

from kingsec.application._support import safe_failure_message
from kingsec.application.ports import AssessmentRepository, AuditPublisher
from kingsec.domain import Assessment
from kingsec.domain.audit import AuditAction, AuditEntry

logger = logging.getLogger(__name__)

_ORPHAN_REASON = (
    "assessment was left RUNNING by a process restart and could not be "
    "resumed; no reliable record exists of what completed before the "
    "interruption"
)


class ResolveOrphanedAssessments:
    """Force every RUNNING assessment found at startup to FAILED.

    Constructor-injected with only the assessment repository and an
    optional audit publisher - this never touches a scanner, job runner,
    or the execution ledger, matching the narrow, structural scope of the
    problem it solves (see module docstring).
    """

    def __init__(self, assessments: AssessmentRepository, audit: AuditPublisher | None = None) -> None:
        self._assessments = assessments
        self._audit = audit

    def execute(self) -> int:
        """Resolve every orphaned RUNNING assessment. Returns the count resolved."""
        orphaned = self._assessments.find_running()
        for assessment in orphaned:
            self._resolve_one(assessment)
        if orphaned:
            logger.warning(
                "orphaned_assessments_resolved_at_startup",
                extra={"event": "orphaned_assessments_resolved_at_startup", "count": len(orphaned)},
            )
        return len(orphaned)

    def _resolve_one(self, assessment: Assessment) -> None:
        assessment_id = str(assessment.id)
        try:
            assessment.fail(_ORPHAN_REASON)
            self._assessments.save(assessment)
        except Exception as exc:  # pragma: no cover - defensive; a single bad
            # row must not abort recovery for every other orphaned assessment.
            logger.warning(
                "failed to resolve orphaned assessment %s: %s",
                assessment_id,
                safe_failure_message(exc),
            )
            return
        self._publish_audit(assessment_id)

    def _publish_audit(self, assessment_id: str) -> None:
        if self._audit is None:
            return
        try:
            self._audit.record(
                AuditEntry(
                    action=AuditAction.ASSESSMENT_FAILED,
                    resource_type="assessment",
                    resource_id=assessment_id,
                    success=True,
                    reason=_ORPHAN_REASON,
                    metadata={"resolved_by": "startup_orphan_recovery"},
                )
            )
        except Exception as exc:
            logger.warning("audit publish failed (best-effort): %s", exc)
