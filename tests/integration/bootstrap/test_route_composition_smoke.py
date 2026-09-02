"""KSEC-91-01: curated real-composition route-contract smoke test.

Phase 90 (KSEC-90-04) concluded that a repo-wide "call every GET route"
smoke framework was NOT warranted: ~40 router modules are mounted
(`adapters/inbound/web/versioning.py`), most GET routes require path
parameters, query parameters, or pre-existing application state a coding
session must not silently invent in a database. Building a safe,
deterministic allowlist for all of them is dedicated-phase-sized work, not
a small addition.

This file is the deliberately SMALL, explicit allowlist Phase 91 asks for
instead - not a generic crawler. It targets exactly one router,
`health_routes.py`, chosen because it uniquely satisfies every safety
criterion at once:

* every route is `GET`, with NO path parameters, NO query parameters, and
  NO request body - nothing to invent;
* none require any pre-existing database state (organization, assessment,
  schedule, plugin, threat feed, or otherwise) - `ProductionServicePort`'s
  use cases (GetHealth, CollectMetrics, ValidateStartup, ...) operate on
  the running process/environment itself, not domain data, so a freshly
  migrated, empty database is exactly the state they're designed for;
* two routes (`/healthz/live`, `/healthz/ready`) require no authentication
  at all - genuinely zero setup;
* the remaining routes are uniformly admin-gated
  (`Depends(require_role(Role.ADMIN))`) - a single synthetic admin
  identity via `dependency_overrides` (this codebase's own established
  test-authentication mechanism, used throughout tests/unit/adapters/
  inbound/web/) covers all of them, with no authorization redesign;
* the mutating siblings in the same file (`POST /healthz/shutdown`,
  `POST /healthz/restart`) are explicitly EXCLUDED - Category D
  (destructive side effect), never candidates for a smoke allowlist;
* the composition chain is genuinely deep and worth exercising for real:
  route -> ProductionServicePort -> ProductionService -> one of 10
  distinct use cases -> SystemMonitorPort / MetricsCollectorPort /
  HealthRepositoryPort / LifecycleManagerPort / LoggingPort / AuditPublisher
  -> their real concrete adapters (SystemHealthMonitor,
  ProcessMetricsCollector, InMemoryHealthRepository, LifecycleManager,
  StructuredLogger). `/healthz/metrics` and `/healthz/resources` both
  reach `MetricsCollectorPort.collect_all()` - the exact port/method the
  Phase 88 `collect_resource_usage()` defect was found in, via a
  different route than the one that originally caught it.

Uses the REAL, fully wired application (`create_wired_application()`, via
the existing `wired_app` fixture from test_composition.py) and the REAL
FastAPI app factory (`create_fastapi_app()`) - the same two functions
production actually calls - never a parallel fake app, never a mocked
port. The only override is the auth *identity* (a synthetic admin/no-auth
test user), never the routes, ports, or adapters under test.

This test proves the WIRING is intact (every route reaches a real,
callable method with a compatible signature and response shape) - it does
NOT attempt to prove business correctness of what each health check
reports, which is exactly the scope KSEC-91-01 asks for.
"""

from __future__ import annotations

import io

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.app import create_fastapi_app
from kingsec.adapters.inbound.web.auth import get_current_user
from kingsec.bootstrap.application import Application
from kingsec.bootstrap.composition import create_wired_application
from kingsec.domain import Role
from kingsec.infrastructure.persistence import create_database_engine, create_schema

_ADMIN_USER = type("User", (), {"id": "smoke-admin", "username": "smoke-admin", "role": Role.ADMIN, "claims": None})()

_TEST_FERNET_KEY = Fernet.generate_key().decode()
_TEST_JWT_SECRET = "test-jwt-secret-" + Fernet.generate_key().decode()
_TEST_PEPPER = "test-pepper-" + Fernet.generate_key().decode()


@pytest.fixture
def wired_app(tmp_path, monkeypatch) -> Application:
    """Deliberately duplicated from test_composition.py's own fixture of
    the same name, rather than imported - importing a same-named pytest
    fixture across modules makes ruff's pyflakes pass treat every test
    function's own `wired_app` parameter as redefining the import
    (F811), and this file must not modify test_composition.py just to
    dodge that. This is intentionally the exact same 3-env-var+create_schema
    shape as the original, kept in sync by inspection, not code sharing."""
    monkeypatch.setenv("KINGSEC_STORAGE__DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KINGSEC_SECRETS__ENCRYPTION_KEY", _TEST_FERNET_KEY)
    monkeypatch.setenv("KINGSEC_JWT__SECRET_KEY", _TEST_JWT_SECRET)
    monkeypatch.setenv("KINGSEC_SECRETS__API_KEY_PEPPER", _TEST_PEPPER)
    engine = create_database_engine(url=f"sqlite:///{tmp_path / 'kingsec.db'}")
    create_schema(engine)
    engine.dispose()
    return create_wired_application(
        log_stream=io.StringIO(),
        ensure_directories=False,
        validate_migrations=False,
    )


def _admin_client(app: Application) -> TestClient:
    fastapi_app = create_fastapi_app(app)
    fastapi_app.dependency_overrides[get_current_user] = lambda: _ADMIN_USER
    return TestClient(fastapi_app)


class TestHealthRoutesUnauthenticated:
    """No dependency override at all - these two routes require none."""

    def test_liveness_route_reaches_the_real_port(self, wired_app: Application) -> None:
        with wired_app as app:
            client = TestClient(create_fastapi_app(app))
            resp = client.get("/api/v1/healthz/live")
            assert resp.status_code == 200
            body = resp.json()
            assert body["alive"] is True

    def test_readiness_route_reaches_the_real_port(self, wired_app: Application) -> None:
        with wired_app as app:
            client = TestClient(create_fastapi_app(app))
            resp = client.get("/api/v1/healthz/ready")
            assert resp.status_code == 200
            assert "ready" in resp.json()


class TestHealthRoutesAdminGated:
    """Same real composition, with a synthetic admin identity override -
    the established dependency_overrides pattern, not a new mechanism."""

    def test_health_route_reaches_get_health_use_case(self, wired_app: Application) -> None:
        with wired_app as app:
            resp = _admin_client(app).get("/api/v1/healthz/health")
            assert resp.status_code == 200

    def test_metrics_route_reaches_collect_metrics_use_case(self, wired_app: Application) -> None:
        """This is the route/port pairing structurally closest to the
        Phase 88 defect: CollectMetrics -> MetricsCollectorPort.collect_all()."""
        with wired_app as app:
            resp = _admin_client(app).get("/api/v1/healthz/metrics")
            assert resp.status_code == 200

    def test_startup_route_reaches_validate_startup_use_case(self, wired_app: Application) -> None:
        with wired_app as app:
            resp = _admin_client(app).get("/api/v1/healthz/startup")
            assert resp.status_code == 200
            assert isinstance(resp.json(), list)

    def test_configuration_route_reaches_validate_configuration_use_case(self, wired_app: Application) -> None:
        with wired_app as app:
            resp = _admin_client(app).get("/api/v1/healthz/configuration")
            assert resp.status_code == 200
            assert isinstance(resp.json(), list)

    def test_dependencies_route_reaches_list_dependencies_use_case(self, wired_app: Application) -> None:
        with wired_app as app:
            resp = _admin_client(app).get("/api/v1/healthz/dependencies")
            assert resp.status_code == 200
            assert isinstance(resp.json(), list)

    def test_resources_route_reaches_get_system_resources_use_case(self, wired_app: Application) -> None:
        """The second route/port pairing reaching
        MetricsCollectorPort.collect_all(), via GetSystemResources rather
        than CollectMetrics - a distinct use case, same underlying port
        method as the metrics test above."""
        with wired_app as app:
            resp = _admin_client(app).get("/api/v1/healthz/resources")
            assert resp.status_code == 200

    def test_performance_route_reaches_collect_metrics_and_cache_port(self, wired_app: Application) -> None:
        with wired_app as app:
            resp = _admin_client(app).get("/api/v1/healthz/performance")
            assert resp.status_code == 200
            body = resp.json()
            assert "cpu_percent" in body


class TestHealthRoutesAuthorizationUnchanged:
    """KSEC-91-01 Section 4.4: this smoke test's purpose is composition
    validation, not a replacement for the authorization suite - this one
    test preserves the existing expectation that admin-gated health
    routes reject a non-admin, using the same real composition, so the
    smoke mechanism itself cannot silently start admitting non-admins."""

    def test_non_admin_is_rejected_from_an_admin_gated_health_route(self, wired_app: Application) -> None:
        with wired_app as app:
            fastapi_app = create_fastapi_app(app)
            viewer = type(
                "User", (), {"id": "smoke-viewer", "username": "smoke-viewer", "role": Role.VIEWER, "claims": None}
            )()
            fastapi_app.dependency_overrides[get_current_user] = lambda: viewer
            resp = TestClient(fastapi_app).get("/api/v1/healthz/health")
            assert resp.status_code == 403


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/healthz/live",
        "/api/v1/healthz/ready",
        "/api/v1/healthz/health",
        "/api/v1/healthz/metrics",
        "/api/v1/healthz/startup",
        "/api/v1/healthz/configuration",
        "/api/v1/healthz/dependencies",
        "/api/v1/healthz/resources",
        "/api/v1/healthz/performance",
    ],
)
def test_no_health_route_returns_a_5xx_through_the_real_composition(path: str, wired_app: Application) -> None:
    """The single assertion this whole allowlist exists to make, applied
    uniformly: every curated route, called through the real wired
    composition with the correct role, must not fail with a server error
    (the Phase 88 defect surfaced as exactly this - an unhandled
    AttributeError becoming a 500). A non-5xx here does not prove the
    business logic is correct; it proves the route -> port -> adapter
    chain is wired to something real and callable."""
    with wired_app as app:
        resp = _admin_client(app).get(path)
        assert resp.status_code < 500, f"{path} returned {resp.status_code}: {resp.text}"
