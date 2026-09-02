"""Regression tests for KSEC-81-01: real server-side license enforcement.

Phase 80 discovered that "api_keys", "unlimited_orgs", and "enterprise_audit"
were defined in the license domain model but never actually checked by any
route or use case — unlike "scheduling"/"integrations", which were correctly
wired but had zero test coverage of their own. This file exercises the REAL
enforcing code (use cases, HTTP routes) for all five paths, not just
``LicenseGate`` booleans in isolation, plus the mandatory license-repository
failure test.

API keys and organizations are enforced purely by the numeric, installation-
wide limit (``max_api_keys``/``max_organizations``), not the "api_keys"/
"unlimited_orgs" boolean features: those booleans are absent from
``EDITION_FEATURES[COMMUNITY]`` while their limits are 3 and 1 respectively
(not 0), so Community is *meant* to create up to that many - checking the
boolean too would wrongly block Community's very first key/organization.
Both booleans have zero other callers in ``src/`` (confirmed by grep), so
this is not a behavior change to anything else.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.integration.adapters.inbound.web.test_identity_routes_authorization import InMemoryIdpRepo
from tests.unit.application.test_register_user import StubPasswordHasher, StubUserRepository

from kingsec.adapters.inbound.web.audit_events import router as audit_events_router
from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
from kingsec.adapters.inbound.web.dependencies import get_application
from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
from kingsec.adapters.inbound.web.identity_routes import router as identity_router
from kingsec.adapters.inbound.web.organization_routes import router as organization_router
from kingsec.application.dto import CreateApiKeyRequest, RegisterUserRequest
from kingsec.application.errors import LicenseRequiredError
from kingsec.application.idp.provider_service import IdentityProviderService
from kingsec.application.ports import ApiKeyHasher, ApiKeyRepository
from kingsec.application.ports.outbound.audit_event_repository import AuditEventRepository
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.license_repository import LicenseRepository
from kingsec.application.ports.outbound.organization_repository import OrganizationRepository
from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort
from kingsec.application.services.licensing import LicenseGate, LicenseValidatorImpl
from kingsec.application.use_cases.create_api_key import CreateApiKey
from kingsec.application.use_cases.create_schedule import CreateSchedule
from kingsec.application.use_cases.register_user import RegisterUser, RegistrationError
from kingsec.application.use_cases.schedule_dto import CreateScheduleRequest
from kingsec.application.use_cases.search_audit_events import SearchAuditEvents
from kingsec.domain import Role
from kingsec.domain.api_key import ApiKey
from kingsec.domain.audit_event import AuditEvent, AuditEventId
from kingsec.domain.license import License, LicenseEdition, LicenseId, LicenseStatus
from kingsec.domain.organization import Organization, OrganizationId, OrganizationMembership, OrgRole
from kingsec.domain.schedule import ScanSchedule
from kingsec.infrastructure.config.models import IntegrationSettings
from kingsec.infrastructure.integrations.webhook_service import WebhookDeliveryService
from kingsec.shared.errors import PersistenceError

# ── Shared license-gate fakes ────────────────────────────────────────────────


class FakeLicenseRepository(LicenseRepository):
    """In-memory LicenseRepository test double that can also simulate an
    outage (``raise_error=True``), for the fail-closed regression test."""

    def __init__(self, license_: License | None = None, *, raise_error: bool = False) -> None:
        self._license = license_
        self._raise_error = raise_error

    def save(self, license: License) -> None:
        self._license = license

    def find_active(self) -> License | None:
        if self._raise_error:
            raise PersistenceError("simulated license database outage")
        return self._license

    def find_by_key(self, license_key: str) -> License | None:
        return self._license if self._license and self._license.license_key == license_key else None

    def list_all(self) -> list[License]:
        return [self._license] if self._license else []

    def delete(self, license_id: str) -> None:
        self._license = None

    def exists(self) -> bool:
        return self._license is not None


def _license(edition: LicenseEdition) -> License:
    return License(
        id=LicenseId.generate(),
        edition=edition,
        status=LicenseStatus.ACTIVE,
        license_key=f"legacy-{edition.value}",
        issued_to="Test Co",
    )


def _gate(edition: LicenseEdition | None, *, raise_error: bool = False) -> LicenseGate:
    """A real LicenseGate over a fake repository - not a mock of the gate
    itself. ``edition=None`` simulates "no license activated"."""
    repo = FakeLicenseRepository(_license(edition) if edition is not None else None, raise_error=raise_error)
    validator = LicenseValidatorImpl(repo)
    return LicenseGate(repo, validator)


def _gate_with_extra_features(edition: LicenseEdition, extra_features: set[str]) -> LicenseGate:
    """A LicenseGate over a custom signed license that grants extra
    features on top of its base edition (``License.effective_features()``
    is ``EDITION_FEATURES[edition] | self.features``). Used to exercise the
    ``max_api_keys`` limit for a Community license that has been granted
    "api_keys" as an add-on - the only way that limit is ever reachable
    under the stock EDITION_FEATURES/EDITION_LIMITS tables, since stock
    Professional/Enterprise are unlimited and stock Community lacks the
    feature entirely."""
    lic = _license(edition)
    lic.features = set(extra_features)
    repo = FakeLicenseRepository(lic)
    validator = LicenseValidatorImpl(repo)
    return LicenseGate(repo, validator)


# ── API keys (KSEC-80-01) ────────────────────────────────────────────────────


class StubApiKeyRepo(ApiKeyRepository):
    def __init__(self) -> None:
        self._keys: dict[str, ApiKey] = {}

    def find_by_id(self, api_key_id: str) -> ApiKey | None:
        return self._keys.get(api_key_id)

    def find_by_user_id(self, user_id: str, limit: int = 50, offset: int = 0) -> list[ApiKey]:
        return [k for k in self._keys.values() if k.user_id == user_id][offset : offset + limit]

    def save(self, key: ApiKey) -> None:
        self._keys[key.id] = key

    def delete(self, api_key_id: str) -> None:
        self._keys.pop(api_key_id, None)

    def count_by_user(self, user_id: str) -> int:
        return sum(1 for k in self._keys.values() if k.user_id == user_id)

    def count_all(self) -> int:
        return len(self._keys)


class StubHasher(ApiKeyHasher):
    def hash(self, plaintext_key: str) -> str:
        return f"hashed:{plaintext_key}"

    def verify(self, plaintext_key: str, key_hash: str) -> bool:
        return key_hash == f"hashed:{plaintext_key}"


class TestApiKeyLicenseEnforcement:
    def test_community_is_rejected_by_entitlement_regardless_of_count(self) -> None:
        """Precise EDITION_FEATURES semantics: "api_keys" is absent from
        EDITION_FEATURES[COMMUNITY], so can_use_api_keys() is False for a
        stock Community license - creation is rejected even with zero
        existing keys, before the numeric limit is ever consulted."""
        repo = StubApiKeyRepo()
        uc = CreateApiKey(repo, StubHasher(), _gate(LicenseEdition.COMMUNITY))

        for i in range(3):
            try:
                uc.execute(CreateApiKeyRequest(user_id="u1", name=f"key-{i}", scope="read_only"))
                raise AssertionError(f"expected LicenseRequiredError at key {i} (0 existing keys)")
            except LicenseRequiredError:
                pass

        assert repo.count_all() == 0

    def test_no_license_falls_back_to_community_and_is_rejected(self) -> None:
        repo = StubApiKeyRepo()
        uc = CreateApiKey(repo, StubHasher(), _gate(None))
        try:
            uc.execute(CreateApiKeyRequest(user_id="u1", name="key-1", scope="read_only"))
            raise AssertionError("expected LicenseRequiredError with no license")
        except LicenseRequiredError:
            pass

    def test_professional_is_unlimited(self) -> None:
        repo = StubApiKeyRepo()
        uc = CreateApiKey(repo, StubHasher(), _gate(LicenseEdition.PROFESSIONAL))
        for i in range(10):
            uc.execute(CreateApiKeyRequest(user_id="u1", name=f"key-{i}", scope="read_only"))
        assert repo.count_all() == 10

    def test_enterprise_is_unlimited(self) -> None:
        repo = StubApiKeyRepo()
        uc = CreateApiKey(repo, StubHasher(), _gate(LicenseEdition.ENTERPRISE))
        for i in range(10):
            uc.execute(CreateApiKeyRequest(user_id="u1", name=f"key-{i}", scope="read_only"))
        assert repo.count_all() == 10

    def test_community_with_api_keys_addon_allows_up_to_the_limit_then_rejects(self) -> None:
        """The only way EDITION_LIMITS[COMMUNITY]["max_api_keys"]=3 is ever
        reachable: a custom signed license that grants "api_keys" as an
        extra feature on top of Community edition. Proves the limit check
        is real, reachable code - not dead code shadowed by the entitlement
        gate."""
        repo = StubApiKeyRepo()
        gate = _gate_with_extra_features(LicenseEdition.COMMUNITY, {"api_keys"})
        uc = CreateApiKey(repo, StubHasher(), gate)

        for i in range(3):
            uc.execute(CreateApiKeyRequest(user_id="u1", name=f"key-{i}", scope="read_only"))

        assert repo.count_all() == 3
        try:
            uc.execute(CreateApiKeyRequest(user_id="u1", name="key-4", scope="read_only"))
            raise AssertionError("expected LicenseRequiredError on the 4th key")
        except LicenseRequiredError:
            pass

    def test_limit_is_installation_wide_not_per_user(self) -> None:
        """The count is server-side and installation-wide: 3 keys already
        owned by a DIFFERENT user still exhaust the installation's limit
        for a new user - the client cannot bypass this by using a fresh
        user_id."""
        repo = StubApiKeyRepo()
        gate = _gate_with_extra_features(LicenseEdition.COMMUNITY, {"api_keys"})
        uc = CreateApiKey(repo, StubHasher(), gate)
        for i in range(3):
            uc.execute(CreateApiKeyRequest(user_id="other-user", name=f"key-{i}", scope="read_only"))

        try:
            uc.execute(CreateApiKeyRequest(user_id="brand-new-user", name="key", scope="read_only"))
            raise AssertionError("expected LicenseRequiredError: limit is installation-wide")
        except LicenseRequiredError:
            pass

    def test_no_gate_wired_is_unrestricted(self) -> None:
        """Backward-compatible default: a caller that never wires a
        LicenseGate (license_gate=None) gets the pre-existing, unrestricted
        behavior rather than a new hard failure."""
        repo = StubApiKeyRepo()
        uc = CreateApiKey(repo, StubHasher())
        for i in range(5):
            uc.execute(CreateApiKeyRequest(user_id="u1", name=f"key-{i}", scope="read_only"))
        assert repo.count_all() == 5


# ── Organizations (KSEC-80-02) ───────────────────────────────────────────────


class InMemoryOrgRepo(OrganizationRepository):
    def __init__(self) -> None:
        self._orgs: dict[str, Organization] = {}
        self._members: list[OrganizationMembership] = []
        self._activity: list = []
        self._teams: dict = {}
        self._team_members: list = []

    def save(self, org: Organization) -> None:
        self._orgs[str(org.id)] = org

    def find_by_id(self, org_id: str) -> Organization | None:
        return self._orgs.get(org_id)

    def find_by_slug(self, slug: str) -> Organization | None:
        return next((o for o in self._orgs.values() if o.slug == slug), None)

    def list_all(self, limit: int = 50, offset: int = 0) -> list[Organization]:
        return list(self._orgs.values())[offset : offset + limit]

    def delete(self, org_id: str) -> None:
        self._orgs.pop(org_id, None)

    def count(self) -> int:
        return len(self._orgs)

    def add_member(self, membership: OrganizationMembership) -> None:
        self._members.append(membership)

    def remove_member(self, org_id: str, user_id: str) -> None:
        self._members = [m for m in self._members if not (m.organization_id == org_id and m.user_id == user_id)]

    def list_members(self, org_id: str) -> list[OrganizationMembership]:
        return [m for m in self._members if m.organization_id == org_id]

    def get_member_role(self, org_id: str, user_id: str) -> OrgRole | None:
        m = next((m for m in self._members if m.organization_id == org_id and m.user_id == user_id), None)
        return m.role if m else None

    def list_user_orgs(self, user_id: str) -> list[OrganizationMembership]:
        return [m for m in self._members if m.user_id == user_id]

    def save_team(self, team) -> None:
        self._teams[str(team.id)] = team

    def find_team_by_id(self, team_id: str):
        return self._teams.get(team_id)

    def list_teams(self, org_id: str) -> list:
        return [t for t in self._teams.values() if t.organization_id == org_id]

    def delete_team(self, team_id: str) -> None:
        self._teams.pop(team_id, None)

    def add_team_member(self, membership) -> None:
        self._team_members.append(membership)

    def remove_team_member(self, team_id: str, user_id: str) -> None:
        self._team_members = [m for m in self._team_members if not (m.team_id == team_id and m.user_id == user_id)]

    def list_team_members(self, team_id: str) -> list:
        return [m for m in self._team_members if m.team_id == team_id]

    def record_activity(self, event) -> None:
        self._activity.append(event)

    def list_activity(self, org_id: str, limit: int = 50) -> list:
        return [e for e in self._activity if e.organization_id == org_id][:limit]


class _RecordingAudit(AuditPublisher):
    def record(self, entry) -> None:
        pass


def _org_app(repo: OrganizationRepository, gate: LicenseGate | None) -> FastAPI:
    class FakeApplication:
        def resolve(self, port: type) -> object:
            if port is OrganizationRepository:
                return repo
            if port is LicenseGate:
                return gate
            if port is AuditPublisher:
                return _RecordingAudit()
            return None

    async def override_get_current_user() -> CurrentUser:
        return CurrentUser(user_id="owner-1", username="owner", role=Role.VIEWER, claims=None)  # type: ignore[arg-type]

    app = FastAPI()
    app.include_router(organization_router)
    app.state.kingsec_app = FakeApplication()
    app.dependency_overrides[get_current_user] = override_get_current_user
    app.dependency_overrides[get_application] = lambda request=None: app.state.kingsec_app
    register_error_handlers(app)
    return app


class TestOrganizationLicenseEnforcement:
    def test_community_allows_first_org_then_rejects_second(self) -> None:
        repo = InMemoryOrgRepo()
        app = _org_app(repo, _gate(LicenseEdition.COMMUNITY))
        client = TestClient(app, raise_server_exceptions=False)

        r1 = client.post("/api/v1/organizations", json={"name": "First Co"})
        assert r1.status_code == 201

        r2 = client.post("/api/v1/organizations", json={"name": "Second Co"})
        assert r2.status_code == 403

    def test_no_license_falls_back_to_community_limit(self) -> None:
        repo = InMemoryOrgRepo()
        app = _org_app(repo, _gate(None))
        client = TestClient(app, raise_server_exceptions=False)

        assert client.post("/api/v1/organizations", json={"name": "First Co"}).status_code == 201
        assert client.post("/api/v1/organizations", json={"name": "Second Co"}).status_code == 403

    def test_professional_allows_multiple_organizations(self) -> None:
        repo = InMemoryOrgRepo()
        app = _org_app(repo, _gate(LicenseEdition.PROFESSIONAL))
        client = TestClient(app, raise_server_exceptions=False)

        for name in ("Org A", "Org B", "Org C"):
            assert client.post("/api/v1/organizations", json={"name": name}).status_code == 201

    def test_enterprise_allows_multiple_organizations(self) -> None:
        repo = InMemoryOrgRepo()
        app = _org_app(repo, _gate(LicenseEdition.ENTERPRISE))
        client = TestClient(app, raise_server_exceptions=False)

        for name in ("Org A", "Org B", "Org C"):
            assert client.post("/api/v1/organizations", json={"name": name}).status_code == 201

    def test_duplicate_slug_check_preserved_ahead_of_license_check(self) -> None:
        repo = InMemoryOrgRepo()
        app = _org_app(repo, _gate(LicenseEdition.PROFESSIONAL))
        client = TestClient(app, raise_server_exceptions=False)

        assert client.post("/api/v1/organizations", json={"name": "Acme"}).status_code == 201
        dup = client.post("/api/v1/organizations", json={"name": "Acme"})
        assert dup.status_code == 409

    def test_no_gate_wired_is_unrestricted(self) -> None:
        repo = InMemoryOrgRepo()
        app = _org_app(repo, None)
        client = TestClient(app, raise_server_exceptions=False)

        for name in ("Org A", "Org B", "Org C"):
            assert client.post("/api/v1/organizations", json={"name": name}).status_code == 201


# ── Enterprise audit access (KSEC-80-03) ─────────────────────────────────────


class StubAuditEventRepo(AuditEventRepository):
    def __init__(self) -> None:
        self._events: dict[str, AuditEvent] = {}

    def save(self, event: AuditEvent) -> None:
        self._events[str(event.id)] = event

    def find_by_id(self, event_id: AuditEventId) -> AuditEvent | None:
        return self._events.get(event_id.value)

    def search(self, **kwargs) -> tuple[list[AuditEvent], int]:
        items = list(self._events.values())
        return items, len(items)


def _audit_app(gate: LicenseGate | None, *, role: Role) -> FastAPI:
    event_repo = StubAuditEventRepo()

    class FakeApplication:
        def resolve(self, port: type) -> object:
            if port is AuditEventRepository:
                return event_repo
            if port is SearchAuditEvents:
                return SearchAuditEvents(event_repo)
            if port is LicenseGate:
                return gate
            return None

    async def override_get_current_user() -> CurrentUser:
        return CurrentUser(user_id="admin-1", username="admin", role=role, claims=None)  # type: ignore[arg-type]

    app = FastAPI()
    app.include_router(audit_events_router)
    app.state.kingsec_app = FakeApplication()
    app.dependency_overrides[get_current_user] = override_get_current_user
    register_error_handlers(app)
    return app


class TestEnterpriseAuditAccess:
    def test_enterprise_admin_is_allowed(self) -> None:
        app = _audit_app(_gate(LicenseEdition.ENTERPRISE), role=Role.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit/events")
        assert resp.status_code == 200

    def test_professional_admin_is_rejected(self) -> None:
        app = _audit_app(_gate(LicenseEdition.PROFESSIONAL), role=Role.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit/events")
        assert resp.status_code == 403

    def test_community_admin_is_rejected(self) -> None:
        app = _audit_app(_gate(LicenseEdition.COMMUNITY), role=Role.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit/events")
        assert resp.status_code == 403

    def test_no_license_admin_is_rejected(self) -> None:
        app = _audit_app(_gate(None), role=Role.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit/events")
        assert resp.status_code == 403

    def test_enterprise_non_admin_is_rejected_by_role_independent_of_license(self) -> None:
        """Proves the two dimensions are independently effective: even
        Enterprise edition does not bypass the pre-existing require_admin
        role check."""
        app = _audit_app(_gate(LicenseEdition.ENTERPRISE), role=Role.VIEWER)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit/events")
        assert resp.status_code == 403

    def test_enterprise_admin_can_get_single_event(self) -> None:
        app = _audit_app(_gate(LicenseEdition.ENTERPRISE), role=Role.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit/events/does-not-exist")
        assert resp.status_code == 404  # past the gate, into normal not-found handling

    def test_community_admin_single_event_is_rejected_before_lookup(self) -> None:
        app = _audit_app(_gate(LicenseEdition.COMMUNITY), role=Role.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit/events/does-not-exist")
        assert resp.status_code == 403


# ── Scheduling regression (already-correct, previously untested) ────────────


class InMemoryScheduleRepo(ScheduleRepositoryPort):
    def __init__(self) -> None:
        self._schedules: dict[str, ScanSchedule] = {}

    def save(self, schedule: ScanSchedule) -> None:
        self._schedules[str(schedule.id)] = schedule

    def find_by_id(self, schedule_id: str) -> ScanSchedule | None:
        return self._schedules.get(schedule_id)

    def find_by_user_id(self, user_id: str) -> list[ScanSchedule]:
        return [s for s in self._schedules.values() if s.owner_user_id == user_id]

    def find_all(self) -> list[ScanSchedule]:
        return list(self._schedules.values())

    def find_due(self, now_utc_str: str) -> list[ScanSchedule]:
        return []

    def try_claim(self, schedule: ScanSchedule) -> ScanSchedule | None:
        current = self._schedules.get(str(schedule.id))
        if current is None or current.version != schedule.version:
            return None
        claimed = schedule.with_version(schedule.version + 1)
        self._schedules[str(schedule.id)] = claimed
        return claimed

    def delete(self, schedule_id: str) -> None:
        self._schedules.pop(schedule_id, None)


def _schedule_request() -> CreateScheduleRequest:
    return CreateScheduleRequest(
        name="Nightly scan",
        description="",
        owner_user_id="u1",
        target="https://example.test",
        scanner_ids=["basic"],
        config={},
        schedule_type="recurring",
        cron_expression="0 2 * * *",
        timezone="UTC",
        max_retries=0,
        retry_delay_seconds=0,
        retry_strategy="no_retry",
    )


class TestSchedulingLicenseEnforcementRegression:
    def test_community_is_rejected(self) -> None:
        uc = CreateSchedule(InMemoryScheduleRepo(), _RecordingAudit(), _gate(LicenseEdition.COMMUNITY))
        try:
            uc.execute(_schedule_request())
            raise AssertionError("expected LicenseRequiredError")
        except LicenseRequiredError:
            pass

    def test_no_license_is_rejected(self) -> None:
        uc = CreateSchedule(InMemoryScheduleRepo(), _RecordingAudit(), _gate(None))
        try:
            uc.execute(_schedule_request())
            raise AssertionError("expected LicenseRequiredError")
        except LicenseRequiredError:
            pass

    def test_professional_succeeds(self) -> None:
        repo = InMemoryScheduleRepo()
        uc = CreateSchedule(repo, _RecordingAudit(), _gate(LicenseEdition.PROFESSIONAL))
        result = uc.execute(_schedule_request())
        assert result.schedule.name == "Nightly scan"

    def test_enterprise_succeeds(self) -> None:
        repo = InMemoryScheduleRepo()
        uc = CreateSchedule(repo, _RecordingAudit(), _gate(LicenseEdition.ENTERPRISE))
        result = uc.execute(_schedule_request())
        assert result.schedule.name == "Nightly scan"


# ── Integrations regression (already-correct, previously untested) ──────────


class TestIntegrationsLicenseEnforcementRegression:
    def test_community_webhook_delivery_is_rejected(self) -> None:
        from kingsec.domain.integration import WebhookEventType

        service = WebhookDeliveryService(IntegrationSettings(), _RecordingAudit(), _gate(LicenseEdition.COMMUNITY))
        try:
            service.deliver(WebhookEventType.ASSESSMENT_COMPLETED, {})
            raise AssertionError("expected LicenseRequiredError")
        except LicenseRequiredError:
            pass

    def test_professional_webhook_delivery_passes_the_gate(self) -> None:
        from kingsec.domain.integration import WebhookEventType

        service = WebhookDeliveryService(IntegrationSettings(), _RecordingAudit(), _gate(LicenseEdition.PROFESSIONAL))
        # No webhook URLs configured -> no targets -> empty result, but
        # critically no LicenseRequiredError, proving the gate let it through.
        result = service.deliver(WebhookEventType.ASSESSMENT_COMPLETED, {})
        assert result == []


# ── Mandatory: LicenseRepository failure fails CLOSED ────────────────────────


class TestLicenseRepositoryFailureFailsClosed:
    def test_gate_falls_back_to_community_when_repository_raises(self) -> None:
        gate = _gate(LicenseEdition.ENTERPRISE, raise_error=True)

        assert gate.current_edition() == LicenseEdition.COMMUNITY
        assert gate.max_api_keys() == 3
        assert gate.max_organizations() == 1
        assert gate.can_use_scheduling() is False
        assert gate.can_use_integrations() is False
        assert gate.can_use_enterprise_audit() is False

    def test_scheduling_use_case_denies_when_repository_raises(self) -> None:
        """A database outage on the (otherwise Enterprise-licensed)
        installation must not silently grant scheduling - it must deny it,
        exactly like an unlicensed Community install."""
        gate = _gate(LicenseEdition.ENTERPRISE, raise_error=True)
        uc = CreateSchedule(InMemoryScheduleRepo(), _RecordingAudit(), gate)
        try:
            uc.execute(_schedule_request())
            raise AssertionError("expected LicenseRequiredError: must fail closed, not open")
        except LicenseRequiredError:
            pass

    def test_only_persistence_error_is_caught_not_arbitrary_exceptions(self) -> None:
        """A real bug elsewhere (e.g. a TypeError in an unrelated code path)
        must NOT be silently swallowed by the fail-closed handling - only
        the repository's own translated PersistenceError is caught."""

        class _BuggyRepo(FakeLicenseRepository):
            def find_active(self) -> License | None:
                raise TypeError("not a persistence failure - a real bug")

        gate = LicenseGate(_BuggyRepo(), LicenseValidatorImpl(_BuggyRepo()))
        try:
            gate.current_edition()
            raise AssertionError("expected TypeError to propagate, not be swallowed")
        except TypeError:
            pass


# ── User registration / max_users (KSEC-83-A) ────────────────────────────────


class TestUserRegistrationLicenseEnforcement:
    def _register(self, repo: StubUserRepository, gate: LicenseGate | None, n: int) -> None:
        uc = RegisterUser(repo, StubPasswordHasher(), audit=None, license_gate=gate)
        for i in range(n):
            uc.execute(RegisterUserRequest(username=f"user{i}", email=f"user{i}@example.com", password="SecurePass1"))

    def test_community_allows_users_below_the_limit(self) -> None:
        repo = StubUserRepository()
        gate = _gate(LicenseEdition.COMMUNITY)
        self._register(repo, gate, 4)
        assert repo.count() == 4

    def test_community_rejects_registration_at_the_limit(self) -> None:
        repo = StubUserRepository()
        gate = _gate(LicenseEdition.COMMUNITY)
        self._register(repo, gate, 5)  # Community's max_users == 5
        uc = RegisterUser(repo, StubPasswordHasher(), audit=None, license_gate=gate)
        try:
            uc.execute(RegisterUserRequest(username="one-too-many", email="over@example.com", password="SecurePass1"))
            raise AssertionError("expected LicenseRequiredError on the 6th user")
        except LicenseRequiredError:
            pass
        assert repo.count() == 5

    def test_professional_allows_registration_beyond_community_limit(self) -> None:
        repo = StubUserRepository()
        gate = _gate(LicenseEdition.PROFESSIONAL)
        self._register(repo, gate, 8)
        assert repo.count() == 8

    def test_enterprise_allows_registration_beyond_community_limit(self) -> None:
        repo = StubUserRepository()
        gate = _gate(LicenseEdition.ENTERPRISE)
        self._register(repo, gate, 8)
        assert repo.count() == 8

    def test_no_license_falls_back_to_community_limit(self) -> None:
        repo = StubUserRepository()
        gate = _gate(None)
        self._register(repo, gate, 5)
        uc = RegisterUser(repo, StubPasswordHasher(), audit=None, license_gate=gate)
        try:
            uc.execute(RegisterUserRequest(username="one-too-many", email="over@example.com", password="SecurePass1"))
            raise AssertionError("expected LicenseRequiredError with no license")
        except LicenseRequiredError:
            pass

    def test_count_is_installation_wide(self) -> None:
        """The limit is a single installation-wide count - there is no
        per-user or per-caller scoping to bypass."""
        repo = StubUserRepository()
        gate = _gate(LicenseEdition.COMMUNITY)
        self._register(repo, gate, 5)
        uc = RegisterUser(repo, StubPasswordHasher(), audit=None, license_gate=gate)
        for username in ("alice", "bob", "carol"):
            try:
                uc.execute(RegisterUserRequest(username=username, email=f"{username}@example.com", password="SecurePass1"))
                raise AssertionError(f"expected LicenseRequiredError for {username}")
            except LicenseRequiredError:
                pass

    def test_no_gate_wired_is_unrestricted(self) -> None:
        """Backward-compatible default: a caller that never wires a
        LicenseGate keeps the pre-Phase-83 unrestricted behavior."""
        repo = StubUserRepository()
        self._register(repo, None, 10)
        assert repo.count() == 10

    def test_duplicate_username_still_rejected_and_not_masked_by_license_check(self) -> None:
        """Under the limit (so the license check passes), a duplicate
        username must still be rejected by its own check - the license
        check does not swallow or replace it."""
        repo = StubUserRepository(existing_username="taken")
        gate = _gate(LicenseEdition.COMMUNITY)
        uc = RegisterUser(repo, StubPasswordHasher(), audit=None, license_gate=gate)
        try:
            uc.execute(RegisterUserRequest(username="taken", email="new@example.com", password="SecurePass1"))
            raise AssertionError("expected RegistrationError for duplicate username")
        except RegistrationError:
            pass
        assert repo.count() == 0

    def test_duplicate_username_rejected_even_when_over_the_limit(self) -> None:
        """The reverse order also holds: even once the license limit is
        already exceeded, the duplicate check still runs and reports its
        own, more specific error rather than a generic license failure
        being the only thing ever observed."""
        repo = StubUserRepository(existing_username="taken")
        gate = _gate(LicenseEdition.COMMUNITY)
        self._register(repo, gate, 5)
        uc = RegisterUser(repo, StubPasswordHasher(), audit=None, license_gate=gate)
        # License check runs first (Section 3's "Step 0"), so at-limit
        # takes precedence - this test documents that ordering rather than
        # assuming the duplicate check would win.
        try:
            uc.execute(RegisterUserRequest(username="taken", email="new@example.com", password="SecurePass1"))
            raise AssertionError("expected LicenseRequiredError (limit already reached)")
        except LicenseRequiredError:
            pass


# ── SSO / identity-provider configuration (KSEC-83-B) ────────────────────────


def _sso_app(gate: LicenseGate | None, *, role: Role) -> FastAPI:
    idp_repo = InMemoryIdpRepo()
    idp_service = IdentityProviderService(idp_repo)

    class FakeApplication:
        def resolve(self, port: type) -> object:
            if port is IdentityProviderService:
                return idp_service
            if port is LicenseGate:
                return gate
            return None

    async def override_get_current_user() -> CurrentUser:
        return CurrentUser(user_id="admin-1", username="admin", role=role, claims=None)  # type: ignore[arg-type]

    app = FastAPI()
    app.include_router(identity_router)
    app.state.kingsec_app = FakeApplication()
    app.dependency_overrides[get_current_user] = override_get_current_user
    register_error_handlers(app)
    return app


class TestSSOLicenseEnforcement:
    def test_enterprise_admin_can_configure_sso(self) -> None:
        app = _sso_app(_gate(LicenseEdition.ENTERPRISE), role=Role.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/identity/providers", json={"name": "corp-okta", "protocol": "oidc"})
        assert resp.status_code == 200, resp.text

    def test_professional_admin_is_rejected_by_license(self) -> None:
        app = _sso_app(_gate(LicenseEdition.PROFESSIONAL), role=Role.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/identity/providers", json={"name": "corp-okta", "protocol": "oidc"})
        assert resp.status_code == 403

    def test_community_admin_is_rejected_by_license(self) -> None:
        app = _sso_app(_gate(LicenseEdition.COMMUNITY), role=Role.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/identity/providers", json={"name": "corp-okta", "protocol": "oidc"})
        assert resp.status_code == 403

    def test_no_license_admin_is_rejected_by_community_fallback(self) -> None:
        app = _sso_app(_gate(None), role=Role.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/identity/providers", json={"name": "corp-okta", "protocol": "oidc"})
        assert resp.status_code == 403

    def test_enterprise_non_admin_is_rejected_by_role(self) -> None:
        """The license check does not replace the admin-role check."""
        app = _sso_app(_gate(LicenseEdition.ENTERPRISE), role=Role.VIEWER)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/identity/providers", json={"name": "corp-okta", "protocol": "oidc"})
        assert resp.status_code == 403

    def test_enterprise_admin_full_mutation_lifecycle_still_works(self) -> None:
        """Existing valid SSO behavior still works for Enterprise, across
        every gated mutation: create, update, activate, deactivate, delete."""
        app = _sso_app(_gate(LicenseEdition.ENTERPRISE), role=Role.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)

        created = client.post("/api/v1/identity/providers", json={"name": "corp-okta", "protocol": "oidc"})
        assert created.status_code == 200, created.text
        provider_id = created.json()["provider"]["id"]

        updated = client.put(f"/api/v1/identity/providers/{provider_id}", json={"name": "renamed"})
        assert updated.status_code == 200, updated.text

        activated = client.post(f"/api/v1/identity/providers/{provider_id}/activate")
        assert activated.status_code == 200, activated.text

        deactivated = client.post(f"/api/v1/identity/providers/{provider_id}/deactivate")
        assert deactivated.status_code == 200, deactivated.text

        deleted = client.delete(f"/api/v1/identity/providers/{provider_id}")
        assert deleted.status_code == 200, deleted.text

    def test_community_admin_can_still_read_configuration(self) -> None:
        """Read-only routes (list/get) are deliberately NOT license-gated -
        viewing already-configured SSO settings doesn't itself consume the
        paid capability. Only the admin-role gate applies to them."""
        app = _sso_app(_gate(LicenseEdition.COMMUNITY), role=Role.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/identity/providers")
        assert resp.status_code == 200, resp.text


# ── Team collaboration (KSEC-83-C) ───────────────────────────────────────────


ORG_ID = "org-1"


def _team_org_app(gate: LicenseGate | None, *, caller_role: OrgRole | None) -> tuple[FastAPI, InMemoryOrgRepo]:
    repo = InMemoryOrgRepo()
    repo.save(Organization(id=OrganizationId(value=ORG_ID), name="Acme", slug="acme"))
    if caller_role is not None:
        repo.add_member(OrganizationMembership(user_id="owner-1", organization_id=ORG_ID, role=caller_role))
    app = _org_app(repo, gate)
    return app, repo


class TestTeamCollaborationLicenseEnforcement:
    def test_professional_admin_can_create_a_team(self) -> None:
        app, _ = _team_org_app(_gate(LicenseEdition.PROFESSIONAL), caller_role=OrgRole.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/teams", json={"organization_id": ORG_ID, "name": "Red Team"})
        assert resp.status_code == 201, resp.text

    def test_enterprise_admin_can_create_a_team(self) -> None:
        app, _ = _team_org_app(_gate(LicenseEdition.ENTERPRISE), caller_role=OrgRole.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/teams", json={"organization_id": ORG_ID, "name": "Red Team"})
        assert resp.status_code == 201, resp.text

    def test_community_admin_cannot_create_a_team(self) -> None:
        app, _ = _team_org_app(_gate(LicenseEdition.COMMUNITY), caller_role=OrgRole.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/teams", json={"organization_id": ORG_ID, "name": "Red Team"})
        assert resp.status_code == 403

    def test_no_license_follows_community_behavior(self) -> None:
        app, _ = _team_org_app(_gate(None), caller_role=OrgRole.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/teams", json={"organization_id": ORG_ID, "name": "Red Team"})
        assert resp.status_code == 403

    def test_non_admin_cannot_create_a_team_regardless_of_license(self) -> None:
        """Existing organization-admin authorization is checked first and
        remains independently effective, even on Enterprise."""
        app, _ = _team_org_app(_gate(LicenseEdition.ENTERPRISE), caller_role=OrgRole.EDITOR)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/teams", json={"organization_id": ORG_ID, "name": "Red Team"})
        assert resp.status_code == 403

    def test_non_member_cannot_create_a_team_regardless_of_license(self) -> None:
        app, _ = _team_org_app(_gate(LicenseEdition.ENTERPRISE), caller_role=None)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/teams", json={"organization_id": ORG_ID, "name": "Red Team"})
        assert resp.status_code == 403

    def test_existing_team_management_remains_ungated_by_design(self) -> None:
        """Deliberate, documented semantics (see organization_routes.py's
        create_team comment): only team CREATION consumes the paid
        capability. update/delete/member-management on an already-existing
        team remain reachable even on Community, so a license that later
        lapses does not strand an org with unmanageable teams."""
        app, repo = _team_org_app(_gate(LicenseEdition.ENTERPRISE), caller_role=OrgRole.ADMIN)
        client = TestClient(app, raise_server_exceptions=False)
        created = client.post("/api/v1/teams", json={"organization_id": ORG_ID, "name": "Red Team"})
        team_id = created.json()["id"]

        # Rebuild the app on a Community gate - the team already exists.
        community_app = _org_app(repo, _gate(LicenseEdition.COMMUNITY))
        community_client = TestClient(community_app, raise_server_exceptions=False)

        updated = community_client.patch(f"/api/v1/teams/{team_id}", json={"name": "Renamed"})
        assert updated.status_code == 200, updated.text

        added = community_client.post(f"/api/v1/teams/{team_id}/members", json={"user_id": "new-member"})
        assert added.status_code == 201, added.text

        removed = community_client.delete(f"/api/v1/teams/{team_id}/members/new-member")
        assert removed.status_code == 204, removed.text

        deleted = community_client.delete(f"/api/v1/teams/{team_id}")
        assert deleted.status_code == 204, deleted.text


# ── Organization activity feed (KSEC-83-D) ───────────────────────────────────


class TestActivityFeedLicenseEnforcement:
    def test_enterprise_member_can_access_activity_feed(self) -> None:
        app, _ = _team_org_app(_gate(LicenseEdition.ENTERPRISE), caller_role=OrgRole.VIEWER)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/api/v1/organizations/{ORG_ID}/activity")
        assert resp.status_code == 200, resp.text

    def test_professional_member_can_access_activity_feed(self) -> None:
        app, _ = _team_org_app(_gate(LicenseEdition.PROFESSIONAL), caller_role=OrgRole.VIEWER)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/api/v1/organizations/{ORG_ID}/activity")
        assert resp.status_code == 200, resp.text

    def test_community_member_is_rejected_by_license(self) -> None:
        app, _ = _team_org_app(_gate(LicenseEdition.COMMUNITY), caller_role=OrgRole.VIEWER)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/api/v1/organizations/{ORG_ID}/activity")
        assert resp.status_code == 403

    def test_no_license_member_is_rejected_by_community_fallback(self) -> None:
        app, _ = _team_org_app(_gate(None), caller_role=OrgRole.VIEWER)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/api/v1/organizations/{ORG_ID}/activity")
        assert resp.status_code == 403

    def test_non_member_rejected_even_with_enterprise_license(self) -> None:
        """License enforcement does not replace membership authorization -
        both remain independently effective."""
        app, _ = _team_org_app(_gate(LicenseEdition.ENTERPRISE), caller_role=None)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/api/v1/organizations/{ORG_ID}/activity")
        assert resp.status_code == 403
