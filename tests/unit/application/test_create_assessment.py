"""CreateAssessment use case."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from tests.unit.application.conftest import InMemoryAssessmentRepository, InMemoryAuthorizationGrantRepository

from kingsec.application import (
    CreateAssessment,
    CreateAssessmentRequest,
    InputValidationError,
)
from kingsec.application.assessment_profiles import ExecutionPlanner
from kingsec.application.errors import AuthorizationScopeError
from kingsec.application.ports import AuditPublisher
from kingsec.application.ports.scanner_registry import ScannerPluginRegistry
from kingsec.application.use_cases.create_assessment import ADMIN_OVERRIDE_AUTHORIZATION_ID
from kingsec.bootstrap.container import Container
from kingsec.domain import (
    AssessmentId,
    AssessmentStatus,
    AuthorizationGrant,
    TargetSpecification,
    TargetSpecificationType,
)
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.identifiers import AuthorizationGrantId
from kingsec.infrastructure.config import Settings
from kingsec.infrastructure.scanner.provisioning import register_scanner


def _request(**overrides: object) -> CreateAssessmentRequest:
    data = {
        "target_value": "10.0.0.5",
        "target_type": "ip_address",
        "authorized_by": "pentester@kingusecurity.com",
        "scope": "10.0.0.5",
    }
    data.update(overrides)
    return CreateAssessmentRequest(**data)  # type: ignore[arg-type]


class TestHappyPath:
    def test_creates_authorized_and_persisted_assessment(self, assessments: InMemoryAssessmentRepository) -> None:
        response = CreateAssessment(assessments).execute(_request())

        # Authorization is captured up front, so the assessment is AUTHORIZED.
        assert response.status == AssessmentStatus.AUTHORIZED.value
        # It was actually persisted and is retrievable.
        stored = assessments.get(AssessmentId(response.assessment_id))
        assert stored.is_authorized is True
        assert stored.status is AssessmentStatus.AUTHORIZED


class TestValidation:
    def test_invalid_target_type_raises_input_error(self, assessments: InMemoryAssessmentRepository) -> None:
        with pytest.raises(InputValidationError, match="invalid target type"):
            CreateAssessment(assessments).execute(_request(target_type="banana"))

    def test_empty_target_value_raises_input_error(self, assessments: InMemoryAssessmentRepository) -> None:
        with pytest.raises(InputValidationError):
            CreateAssessment(assessments).execute(_request(target_value="  "))

    def test_unknown_profile_is_rejected_before_persistence(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        with pytest.raises(InputValidationError, match="Unknown profile"):
            CreateAssessment(assessments).execute(_request(profile_id="not-a-real-profile"))
        assert assessments.list().items == ()

    def test_profile_target_mismatch_is_rejected_before_persistence(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        with pytest.raises(InputValidationError, match="does not support target type"):
            CreateAssessment(assessments).execute(
                _request(
                    target_value="https://example.com",
                    target_type="url",
                    profile_id="quick-scan",
                )
            )
        assert assessments.list().items == ()


# ---------------------------------------------------------------------------
# Phase 4: authorization scope enforcement
# ---------------------------------------------------------------------------


def _real_registry() -> ScannerPluginRegistry:
    """The REAL scanner plugin registry, wired exactly as
    infrastructure.scanner.provisioning.register_scanner() does - matches
    the precedent used throughout Phase 4's own test suite."""
    container = Container()
    register_scanner(container, Settings())
    return container.resolve(ScannerPluginRegistry)  # type: ignore[return-value]


def _grant(
    spec: TargetSpecification,
    *,
    valid_from: datetime = datetime(2020, 1, 1, tzinfo=UTC),
    valid_until: datetime = datetime(2099, 1, 1, tzinfo=UTC),
) -> AuthorizationGrant:
    return AuthorizationGrant(
        id=AuthorizationGrantId.generate(),
        authorized_by="ciso@example.com",
        authorizing_organization="Example Corp",
        target_specification=spec,
        valid_from=valid_from,
        valid_until=valid_until,
        created_by="admin@kingusecurity.com",
    )


class TestAuthorizationScopeEnforcementUnconfigured:
    def test_creates_assessment_without_a_scope_check_when_unconfigured(
        self,
        assessments: InMemoryAssessmentRepository,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Fail-open, but LOUD - see CreateAssessment.__init__'s docstring
        comment. profile_id is set (so there IS something a real check
        would evaluate) and the assessment is still created, because
        grants/registry/planner were never supplied - the transitional
        state pending Phase 4's migration-approval step, not a silent
        gap: it must log a warning every time."""
        import logging

        with caplog.at_level(logging.WARNING):
            response = CreateAssessment(assessments).execute(_request(profile_id="quick-scan"))
        assert response.status == AssessmentStatus.AUTHORIZED.value
        assert any("not configured" in record.message for record in caplog.records)


class TestAuthorizationScopeEnforcementConfigured:
    def test_creates_assessment_when_a_covering_grant_exists(
        self,
        assessments: InMemoryAssessmentRepository,
        authorization_grants: InMemoryAuthorizationGrantRepository,
    ) -> None:
        authorization_grants.save(_grant(TargetSpecification(TargetSpecificationType.IP_ADDRESS, "10.0.0.5")))
        use_case = CreateAssessment(
            assessments, grants=authorization_grants, registry=_real_registry(), planner=ExecutionPlanner()
        )
        response = use_case.execute(_request(profile_id="quick-scan"))
        assert response.status == AssessmentStatus.AUTHORIZED.value

    @pytest.mark.parametrize(
        ("profile_id", "target_type", "target_value", "specification_type"),
        [
            (
                "code-review",
                "source_path",
                "/srv/customer/source",
                TargetSpecificationType.SOURCE_PATH,
            ),
            (
                "container-scan",
                "container_image",
                "registry.example.com/team/app:v1",
                TargetSpecificationType.CONTAINER_IMAGE,
            ),
            (
                "domain-enumeration",
                "domain",
                "example.com",
                TargetSpecificationType.DOMAIN,
            ),
        ],
    )
    def test_purpose_built_profile_requires_and_records_its_exact_resource_grant(
        self,
        assessments: InMemoryAssessmentRepository,
        authorization_grants: InMemoryAuthorizationGrantRepository,
        profile_id: str,
        target_type: str,
        target_value: str,
        specification_type: TargetSpecificationType,
    ) -> None:
        grant = _grant(TargetSpecification(specification_type, target_value))
        authorization_grants.save(grant)
        use_case = CreateAssessment(
            assessments,
            grants=authorization_grants,
            registry=_real_registry(),
            planner=ExecutionPlanner(),
        )

        response = use_case.execute(
            _request(
                target_value=target_value,
                target_type=target_type,
                profile_id=profile_id,
                scope=target_value,
            )
        )

        stored = assessments.get(AssessmentId(response.assessment_id))
        assert stored.authorization_id == str(grant.id)

    def test_refuses_and_persists_nothing_when_no_covering_grant_exists(
        self,
        assessments: InMemoryAssessmentRepository,
        authorization_grants: InMemoryAuthorizationGrantRepository,
    ) -> None:
        use_case = CreateAssessment(
            assessments, grants=authorization_grants, registry=_real_registry(), planner=ExecutionPlanner()
        )
        with pytest.raises(AuthorizationScopeError):
            use_case.execute(_request(profile_id="quick-scan"))
        # Never creates then blocks: nothing was persisted.
        assert assessments.list().items == ()

    def test_refuses_when_the_only_grant_covers_a_different_tier(
        self,
        assessments: InMemoryAssessmentRepository,
        authorization_grants: InMemoryAuthorizationGrantRepository,
    ) -> None:
        """quick-scan against an IP_ADDRESS target requires HOST_ANY_PORT
        (nmap). A URL-scoped grant never satisfies that tier (Blocking 1) -
        confirms enforcement is genuinely tier-aware, not just
        target-string matching."""
        authorization_grants.save(_grant(TargetSpecification(TargetSpecificationType.URL_PREFIX, "https://10.0.0.5/")))
        use_case = CreateAssessment(
            assessments, grants=authorization_grants, registry=_real_registry(), planner=ExecutionPlanner()
        )
        with pytest.raises(AuthorizationScopeError):
            use_case.execute(_request(profile_id="quick-scan"))

    def test_no_profile_is_refused_when_no_grant_covers_its_real_scan_surface(
        self,
        assessments: InMemoryAssessmentRepository,
        authorization_grants: InMemoryAuthorizationGrantRepository,
    ) -> None:
        """No profile executes every compatible scanner; it must never
        bypass the authorization gate merely because there is no profile
        object from which to start the surface derivation."""
        use_case = CreateAssessment(
            assessments, grants=authorization_grants, registry=_real_registry(), planner=ExecutionPlanner()
        )
        with pytest.raises(AuthorizationScopeError):
            use_case.execute(_request())
        assert assessments.list().items == ()

    def test_no_profile_records_grant_covering_every_compatible_scanner(
        self,
        assessments: InMemoryAssessmentRepository,
        authorization_grants: InMemoryAuthorizationGrantRepository,
    ) -> None:
        grant = _grant(TargetSpecification(TargetSpecificationType.IP_ADDRESS, "10.0.0.5"))
        authorization_grants.save(grant)
        use_case = CreateAssessment(
            assessments, grants=authorization_grants, registry=_real_registry(), planner=ExecutionPlanner()
        )

        response = use_case.execute(_request())

        stored = assessments.get(AssessmentId(response.assessment_id))
        assert stored.authorization_id == str(grant.id)

    def test_persisted_assessment_carries_the_covering_grants_id_and_it_is_retrievable(
        self,
        assessments: InMemoryAssessmentRepository,
        authorization_grants: InMemoryAuthorizationGrantRepository,
    ) -> None:
        grant = _grant(TargetSpecification(TargetSpecificationType.IP_ADDRESS, "10.0.0.5"))
        authorization_grants.save(grant)
        use_case = CreateAssessment(
            assessments, grants=authorization_grants, registry=_real_registry(), planner=ExecutionPlanner()
        )
        response = use_case.execute(_request(profile_id="quick-scan"))

        stored = assessments.get(AssessmentId(response.assessment_id))
        assert stored.authorization_id == str(grant.id)
        # Retrievable: the recorded id genuinely resolves back to the real
        # grant that covered this assessment - not just a string that
        # happens to look right.
        assert authorization_grants.get(AuthorizationGrantId(stored.authorization_id)) == grant

    def test_tiers_covered_by_different_grants_records_both_ids(
        self,
        assessments: InMemoryAssessmentRepository,
        authorization_grants: InMemoryAuthorizationGrantRepository,
    ) -> None:
        """web-scan against a URL target requires three tiers -
        HOST_ANY_PORT, HOST_PORT_PATH, HOST_PORT_ANY_PATH (see
        test_authorization_scope.py's own derivation). satisfies_tier()
        explicitly refuses a URL-scoped grant for HOST_ANY_PORT ("a
        separate host-level grant is required"), so a URL-prefix grant and
        a hostname grant genuinely need EACH OTHER to jointly cover every
        required tier here - this proves authorization_id records both
        ids, never silently collapsing to whichever grant matched first."""
        narrow = _grant(TargetSpecification(TargetSpecificationType.URL_PREFIX, "https://scan.example.com:8443/app/"))
        broad = _grant(TargetSpecification(TargetSpecificationType.HOSTNAME, "scan.example.com"))
        authorization_grants.save(narrow)
        authorization_grants.save(broad)
        use_case = CreateAssessment(
            assessments, grants=authorization_grants, registry=_real_registry(), planner=ExecutionPlanner()
        )
        response = use_case.execute(
            _request(
                target_value="https://scan.example.com:8443/app/",
                target_type="url",
                profile_id="web-scan",
                scope="https://scan.example.com:8443/app/",
            )
        )

        stored = assessments.get(AssessmentId(response.assessment_id))
        assert stored.authorization_id is not None
        recorded_ids = set(stored.authorization_id.split(","))
        assert recorded_ids == {str(narrow.id), str(broad.id)}


class _RecordingAuditPublisher(AuditPublisher):
    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        self.entries.append(entry)


class TestAuthorizationScopeAuditTrail:
    def test_refusal_publishes_scope_check_refused_before_raising(
        self,
        assessments: InMemoryAssessmentRepository,
        authorization_grants: InMemoryAuthorizationGrantRepository,
    ) -> None:
        audit = _RecordingAuditPublisher()
        use_case = CreateAssessment(
            assessments,
            audit=audit,
            grants=authorization_grants,
            registry=_real_registry(),
            planner=ExecutionPlanner(),
        )
        with pytest.raises(AuthorizationScopeError):
            use_case.execute(_request(profile_id="quick-scan"))

        assert len(audit.entries) == 1
        entry = audit.entries[0]
        assert entry.action == AuditAction.SCOPE_CHECK_REFUSED
        assert entry.success is False
        assert "host_any_port" in entry.metadata["missing_tiers"]
        # Never creates then blocks: nothing was persisted either.
        assert assessments.list().items == ()

    def test_admin_override_creates_the_assessment_and_publishes_scope_check_overridden(
        self,
        assessments: InMemoryAssessmentRepository,
        authorization_grants: InMemoryAuthorizationGrantRepository,
    ) -> None:
        audit = _RecordingAuditPublisher()
        use_case = CreateAssessment(
            assessments,
            audit=audit,
            grants=authorization_grants,
            registry=_real_registry(),
            planner=ExecutionPlanner(),
        )
        response = use_case.execute(
            _request(profile_id="quick-scan", requesting_is_admin=True, override_scope_check=True)
        )

        assert response.status == AssessmentStatus.AUTHORIZED.value
        overridden = [e for e in audit.entries if e.action == AuditAction.SCOPE_CHECK_OVERRIDDEN]
        assert len(overridden) == 1
        assert overridden[0].success is True
        assert "host_any_port" in overridden[0].metadata["missing_tiers"]
        # The normal creation audit entry still fires too - an override
        # is visible in the trail, never in place of the usual record.
        assert any(e.action == AuditAction.ASSESSMENT_CREATED for e in audit.entries)
        # And the assessment really was persisted.
        stored = assessments.get(AssessmentId(response.assessment_id))
        assert stored is not None
        # The override is recorded on the row itself too, distinguishable
        # from both "covered by grant X" (a real "agrt-" id) and
        # "pre-enforcement" (None).
        assert stored.authorization_id == ADMIN_OVERRIDE_AUTHORIZATION_ID

    def test_override_flag_alone_without_admin_is_still_refused(
        self,
        assessments: InMemoryAssessmentRepository,
        authorization_grants: InMemoryAuthorizationGrantRepository,
    ) -> None:
        """A non-admin cannot self-grant the override by setting the flag -
        override_scope_check is only honored together with
        requesting_is_admin, and CreateAssessment never re-derives that
        role itself; a caller lying about requesting_is_admin is the
        inbound route's problem to prevent, not this test's - this test
        only proves the flag alone is not sufficient."""
        audit = _RecordingAuditPublisher()
        use_case = CreateAssessment(
            assessments,
            audit=audit,
            grants=authorization_grants,
            registry=_real_registry(),
            planner=ExecutionPlanner(),
        )
        with pytest.raises(AuthorizationScopeError):
            use_case.execute(_request(profile_id="quick-scan", override_scope_check=True, requesting_is_admin=False))
        assert any(e.action == AuditAction.SCOPE_CHECK_REFUSED for e in audit.entries)
        assert not any(e.action == AuditAction.SCOPE_CHECK_OVERRIDDEN for e in audit.entries)

    def test_admin_without_override_flag_is_still_refused(
        self,
        assessments: InMemoryAssessmentRepository,
        authorization_grants: InMemoryAuthorizationGrantRepository,
    ) -> None:
        """Being an admin alone does not bypass the check - the override
        must be explicitly requested."""
        use_case = CreateAssessment(
            assessments, grants=authorization_grants, registry=_real_registry(), planner=ExecutionPlanner()
        )
        with pytest.raises(AuthorizationScopeError):
            use_case.execute(_request(profile_id="quick-scan", requesting_is_admin=True, override_scope_check=False))
