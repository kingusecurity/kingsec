"""Use case: create a new assessment.

Design note — authorization is captured at creation. KingSec is trust-first: you
should never hold an assessment you weren't authorized to run. So this use case
records the ``Authorization`` immediately, leaving the assessment in the
AUTHORIZED state (ready to start). A separate "authorize later" flow could be
added as its own use case if the product ever needs a draft-then-approve step.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from kingsec.application._support import build_target
from kingsec.application.assessment_profiles import ExecutionPlanner
from kingsec.application.authorization_scope import effective_scan_surface, find_covering
from kingsec.application.dto import CreateAssessmentRequest, CreateAssessmentResponse
from kingsec.application.errors import AuthorizationScopeError
from kingsec.application.events import EVENT_ASSESSMENT_CREATED, AssessmentEvent
from kingsec.application.ports import (
    AssessmentRepository,
    AuditPublisher,
    AuthorizationGrantRepository,
    EventPublisher,
)
from kingsec.application.ports.scanner_registry import ScannerPluginRegistry
from kingsec.domain import Assessment, Authorization, Target
from kingsec.domain.audit import AuditAction, AuditEntry

# Phase 4: the sentinel Assessment.authorization_id carries when an admin
# used override_scope_check to bypass a refusal. Never matches a real grant
# id (AuthorizationGrantId.generate() always produces "agrt-<hex>"), so it
# is structurally distinguishable from "covered by grant X" - and, being
# non-None, from "pre-enforcement" (NULL) too.
ADMIN_OVERRIDE_AUTHORIZATION_ID = "admin-override"


class CreateAssessment:
    """Create, authorize, and persist a new assessment."""

    def __init__(
        self,
        assessments: AssessmentRepository,
        events: EventPublisher | None = None,
        audit: AuditPublisher | None = None,
        grants: AuthorizationGrantRepository | None = None,
        registry: ScannerPluginRegistry | None = None,
        planner: ExecutionPlanner | None = None,
    ) -> None:
        # Constructor injection: the use case depends on the ABSTRACT port, not a
        # concrete repository. The composition root supplies the real one.
        self._assessments = assessments
        self._events = events
        self._audit = audit
        # Phase 4 (authorization scope enforcement): all three optional
        # until the composition root is updated to supply the real
        # AuthorizationGrantRepository adapter (pending the migration this
        # feature's own approval process gates - see docs/STATUS.md). Not
        # a silent gap: _enforce_authorization_scope() logs a warning on
        # every call while unconfigured, and this comment plus that log
        # line are the record of why - never leave a security check able
        # to no-op without a trace (the exact failure mode a now-deleted
        # phantom setting, require_authorization, described in its own
        # docstring while enforcing nothing).
        self._grants = grants
        self._registry = registry
        self._planner = planner

    def execute(self, request: CreateAssessmentRequest) -> CreateAssessmentResponse:
        # Translate raw primitives into a validated domain Target (raises
        # InputValidationError on bad input).
        target = build_target(request.target_value, request.target_type)

        authorization_id = self._enforce_authorization_scope(target, request)

        assessment = Assessment.create(
            target,
            profile_id=request.profile_id,
            schedule_occurrence_id=request.schedule_occurrence_id,
            authorization_id=authorization_id,
        )
        if request.owner_id:
            assessment.set_ownership(request.owner_id)
        authorization = Authorization.grant(request.authorized_by, request.scope)
        assessment.authorize(authorization)

        self._assessments.save(assessment)

        self._publish_event(
            AssessmentEvent(
                event_type=EVENT_ASSESSMENT_CREATED,
                assessment_id=str(assessment.id),
                state=assessment.status.value,
                message=f"Assessment created for {assessment.target}",
                owner_id=assessment.owner_id,
            )
        )

        self._publish_audit(
            AuditEntry(
                action=AuditAction.ASSESSMENT_CREATED,
                resource_type="assessment",
                resource_id=str(assessment.id),
                success=True,
                user_id=request.owner_id,
                username=request.requesting_username,
                metadata={"target": str(assessment.target), "authorized_by": request.authorized_by},
            )
        )

        return CreateAssessmentResponse(
            assessment_id=str(assessment.id),
            status=assessment.status.value,
            target=str(assessment.target),
        )

    def _enforce_authorization_scope(self, target: Target, request: CreateAssessmentRequest) -> str | None:
        """Phase 4: refuse to create an assessment whose target is not
        covered, at every ScannerSurfaceTier a scanner in the requested
        profile would actually touch, by an active AuthorizationGrant.

        Returns the value to persist as Assessment.authorization_id:
          - None: enforcement not configured, no profile, unknown profile,
            or no ScannerSurfaceTier actually required a grant - nothing
            was checked, so nothing is recorded (see the field's own
            docstring in domain/assessment.py for why None is honest here,
            not just "pre-enforcement").
          - a single grant id, or several comma-joined: every required
            tier was covered, by find_covering()'s actual match(es). More
            than one distinct grant can legitimately be needed - e.g. a
            profile requiring both HOST_ANY_PORT (nmap) and a narrower
            path-scoped tier, where a broad host-level grant satisfies the
            former and a URL-prefix grant satisfies the latter
            (satisfies_tier() explicitly refuses a URL-scoped grant for
            HOST_ANY_PORT). Recording only one id in that case would
            misstate the audit trail.
          - ADMIN_OVERRIDE_AUTHORIZATION_ID: the admin-override path fired.

        Fails BEFORE the assessment is created - KingSec never creates
        then blocks; it refuses to create the unauthorized work at all.

        Fails OPEN (logs a warning, does not enforce) only while grants/
        registry/planner are not yet wired at the composition root - see
        __init__'s docstring comment for why this is a deliberate,
        explicitly-logged transitional state, not a silent gap.

        Admin override: request.override_scope_check is only ever honored
        together with request.requesting_is_admin - both trusted as
        already vetted by the inbound route (see CreateAssessmentRequest's
        own field comment). An override still produces an audit entry
        (SCOPE_CHECK_OVERRIDDEN), naming every missing tier, so bypassing
        the check is exactly as visible in the audit trail as being
        refused by it (SCOPE_CHECK_REFUSED) - never a silent bypass.
        """
        if self._grants is None or self._registry is None or self._planner is None:
            logging.getLogger(__name__).warning(
                "authorization scope enforcement is not configured - assessment created for %r without a scope check",
                target.value,
            )
            return None

        profile_id = request.profile_id
        if profile_id is None:
            # No profile chosen yet is a different validity concern,
            # handled elsewhere (e.g. execution planning) - nothing to
            # enforce a scan surface against here.
            return None
        profile = self._planner.get_profile(profile_id)
        if profile is None:
            # An unknown profile_id is likewise a different validity
            # concern, handled elsewhere.
            return None

        required_tiers = effective_scan_surface(profile, self._registry, target.type)
        if not required_tiers:
            return None

        now = datetime.now(UTC)
        active_grants = self._grants.find_active(now)
        matched_grant_ids: set[str] = set()
        missing_tiers: list[str] = []
        for tier in sorted(required_tiers, key=lambda t: t.value):
            grant = find_covering(active_grants, target, tier, now)
            if grant is None:
                missing_tiers.append(tier.value)
            else:
                matched_grant_ids.add(str(grant.id))
        missing_tiers.sort()

        if not missing_tiers:
            return ",".join(sorted(matched_grant_ids))

        audit_metadata: dict[str, object] = {
            "target": target.value,
            "profile_id": profile_id,
            "missing_tiers": ",".join(missing_tiers),
        }

        if request.override_scope_check and request.requesting_is_admin:
            self._publish_audit(
                AuditEntry(
                    action=AuditAction.SCOPE_CHECK_OVERRIDDEN,
                    resource_type="assessment",
                    resource_id=target.value,
                    success=True,
                    user_id=request.owner_id,
                    username=request.requesting_username,
                    metadata=audit_metadata,
                )
            )
            return ADMIN_OVERRIDE_AUTHORIZATION_ID

        self._publish_audit(
            AuditEntry(
                action=AuditAction.SCOPE_CHECK_REFUSED,
                resource_type="assessment",
                resource_id=target.value,
                success=False,
                reason=f"no active grant covers {target.value!r} for: {', '.join(missing_tiers)}",
                user_id=request.owner_id,
                username=request.requesting_username,
                metadata=audit_metadata,
            )
        )
        raise AuthorizationScopeError(target.value, missing_tiers[0])

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
