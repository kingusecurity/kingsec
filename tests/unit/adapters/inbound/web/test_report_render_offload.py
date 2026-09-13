"""Phase 2B-c Priority 2 acceptance test: rendering a large report must not
block the event loop (5c). This is the user-specified acceptance criterion
verbatim: "rendering a 4,000-finding report leaves /health responsive
throughout." Proven with real wall-clock concurrency, not a mock assertion -
a fake ReportGeneratorPort blocks for several seconds (standing in for
WeasyPrint rendering ~4,000 findings), fired on one thread, while a second
thread hits /health concurrently and must get an immediate response.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user, require_viewer
from kingsec.application import RenderedReport, ReportGeneratorPort
from kingsec.application.ports import TokenClaims
from kingsec.domain import Assessment, Authorization, Finding, Report, Severity, Target, TargetType
from kingsec.domain.enums import Role

# Stands in for WeasyPrint rendering ~4,000 findings - long enough that a
# blocked event loop would make the concurrent /health call visibly wait,
# short enough to keep the test fast when the fix is working.
_SLOW_RENDER_SECONDS = 2.5


class _SlowReportGenerator(ReportGeneratorPort):
    """A ReportGeneratorPort whose render() blocks synchronously - exactly
    the shape of a real, un-offloaded WeasyPrint call."""

    def render(self, report: Report, *, format: str | None = None) -> RenderedReport:
        time.sleep(_SLOW_RENDER_SECONDS)
        return RenderedReport(content=b"%PDF-fake-large-report", media_type="application/pdf", filename="r.pdf")


class _FakeAssessmentRepository:
    def __init__(self, assessment: Assessment) -> None:
        self._assessment = assessment

    def get(self, assessment_id: object) -> Assessment:
        return self._assessment


class _FakeReportRepository:
    def __init__(self, report: Report) -> None:
        self._report = report

    def get(self, assessment_id: object) -> Report:
        return self._report


def _admin_user() -> CurrentUser:
    now = datetime.now(UTC)
    return CurrentUser(
        user_id="admin-001",
        username="admin",
        role=Role.ADMIN,
        claims=TokenClaims(
            user_id="admin-001",
            username="admin",
            role="admin",
            token_type="access",
            jti="jti-admin-001",
            issued_at=now,
            expires_at=now,
        ),
    )


def _build_assessment_and_report() -> tuple[Assessment, Report]:
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessment.start()
    assessment.record_finding(Finding.create("SQL Injection", "id param injectable", Severity.CRITICAL))
    assessment.complete()
    return assessment, Report.from_assessment(assessment)


@pytest.fixture
def slow_download_client() -> Iterator[TestClient]:
    """A real FastAPI app wired with the actual routes, a slow (blocking)
    ReportGeneratorPort, and the actual asyncio.to_thread offload added in
    routes.py's download_report().

    Entered as a context manager deliberately: TestClient only shares a
    single event-loop portal across concurrent .get() calls while its
    `with` block is open (starlette.testclient.TestClient._portal_factory
    creates a fresh, isolated portal per call otherwise) - without this,
    two concurrent requests run on two separate event loops regardless of
    whether the route offloads its blocking work, and this test would
    pass even with the 5c fix reverted (verified empirically).
    """
    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router
    from kingsec.application.ports import AssessmentRepository, ReportRepository
    from kingsec.application.ports import ReportGeneratorPort as ReportGeneratorPortType

    assessment, report = _build_assessment_and_report()
    ports = {
        AssessmentRepository: _FakeAssessmentRepository(assessment),
        ReportRepository: _FakeReportRepository(report),
        ReportGeneratorPortType: _SlowReportGenerator(),
    }

    class _StubApp:
        def resolve(self, service_type: type) -> object:
            return ports[service_type]

    app = FastAPI()
    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]
    register_error_handlers(app)
    app.include_router(router)

    admin = _admin_user()
    app.dependency_overrides[get_current_user] = lambda: admin
    app.dependency_overrides[require_viewer] = lambda: admin

    with TestClient(app, raise_server_exceptions=False) as client:
        client.state_assessment_id = str(assessment.id)  # type: ignore[attr-defined]
        yield client


class TestReportRenderDoesNotBlockEventLoop:
    def test_health_stays_responsive_while_a_slow_report_renders(self, slow_download_client: TestClient) -> None:
        assessment_id = slow_download_client.state_assessment_id  # type: ignore[attr-defined]

        with ThreadPoolExecutor(max_workers=2) as pool:
            slow_future = pool.submit(slow_download_client.get, f"/api/v1/reports/{assessment_id}/download")
            time.sleep(_SLOW_RENDER_SECONDS / 2)  # let the slow render actually start

            health_start = time.monotonic()
            health_response = slow_download_client.get("/api/v1/health")
            health_elapsed = time.monotonic() - health_start

            slow_response = slow_future.result(timeout=_SLOW_RENDER_SECONDS + 5)

        assert slow_response.status_code == 200
        assert health_response.status_code == 200
        # The acceptance criterion: /health must not wait behind the slow
        # render. A blocked event loop would make this take ~_SLOW_RENDER_SECONDS
        # (or the remainder of it); a correctly offloaded render leaves it
        # near-instant regardless of what's rendering in the background.
        assert health_elapsed < _SLOW_RENDER_SECONDS / 2, (
            f"/health took {health_elapsed:.2f}s while a report was rendering - "
            "the event loop appears blocked (Phase 2B-c Priority 2, 5c regression)"
        )
