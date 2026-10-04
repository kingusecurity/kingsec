"""Phase 2C Step 2, GAP-1 follow-up: the refusal Report.from_assessment()
applies at GENERATION time (a FAILED assessment - zero scanners succeeded -
must never produce a scored report) must also apply on the READ path.

Phase 2B-c Priority 2 added a report cache: /reports/{id}/download can serve
a STORED artifact without ever calling from_assessment() again. A report
generated before derive_assessment_status() existed can still be sitting in
the database with a stale assessment_status - GET /reports/{id} and
GET /reports/{id}/download must refuse to read/serve it, with the same
reason generation-time uses, rather than silently resurfacing the false
claim from cache.

Built against the REAL stale-row shape (asmt-1983c7e4b1564815b62bb0bf02dc3e08
in C:\\kingsec-e2e\\kingsec.db): status persisted as COMPLETED via a bare
.complete() call, but scanner_summary shows zero of five scanners actually
succeeded.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user, require_viewer
from kingsec.application import RenderedReport, ReportGeneratorPort
from kingsec.application.ports import TokenClaims
from kingsec.domain import Assessment, Authorization, Report, ScannerRunSummary, Target, TargetType
from kingsec.domain.enums import Role, ScannerRunState

# The exact real shape of asmt-1983c7e4b1564815b62bb0bf02dc3e08 in
# C:\kingsec-e2e\kingsec.db.
_STALE_ROW_SUMMARY = (
    ScannerRunSummary(scanner_id="nmap", name="Nmap", status=ScannerRunState.PENDING),
    ScannerRunSummary(
        scanner_id="gobuster",
        name="Gobuster",
        status=ScannerRunState.FAILED,
        skipped_reason="wordlist could not be found",
    ),
    ScannerRunSummary(
        scanner_id="ffuf",
        name="FFUF",
        status=ScannerRunState.FAILED,
        skipped_reason="wordlist could not be found",
    ),
    ScannerRunSummary(
        scanner_id="zap",
        name="OWASP ZAP",
        status=ScannerRunState.FAILED,
        skipped_reason="scan process exited with an error",
    ),
    ScannerRunSummary(
        scanner_id="nuclei",
        name="Nuclei",
        status=ScannerRunState.SKIPPED_INCOMPATIBLE,
        skipped_reason="Missing Nuclei templates",
    ),
)


def _stale_row_assessment() -> Assessment:
    assessment = Assessment.create(Target("http://127.0.0.1:18080", TargetType.URL))
    assessment.authorize(Authorization.grant("tester", scope="http://127.0.0.1:18080"))
    assessment.start()
    assessment.record_scanner_summary(_STALE_ROW_SUMMARY)
    assessment.complete()  # the bug: an old/buggy write path called this unconditionally
    assert assessment.status.value == "completed"  # confirms the contradiction genuinely exists
    return assessment


class _FakeAssessmentRepository:
    def __init__(self, assessment: Assessment) -> None:
        self._assessment = assessment

    def get(self, assessment_id: object) -> Assessment:
        return self._assessment


class _RefusingReportRepository:
    """Raises if .get() is ever called - proves the refusal happens BEFORE
    any stored/cached report is read, not merely that its content gets
    discarded afterward."""

    def get(self, assessment_id: object) -> Report:
        raise AssertionError("ReportRepository.get() must not be called once the assessment is refused")


class _UnreachableReportGenerator(ReportGeneratorPort):
    """Raises if .render() is ever called - proves the cache is never
    consulted once the assessment is refused."""

    def render(self, report: Report, *, format: str | None = None) -> RenderedReport:
        raise AssertionError("ReportGeneratorPort.render() must not be called once the assessment is refused")


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


@pytest.fixture
def stale_row_client() -> Iterator[TestClient]:
    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router
    from kingsec.application.ports import AssessmentRepository, ReportRepository
    from kingsec.application.ports import ReportGeneratorPort as ReportGeneratorPortType

    assessment = _stale_row_assessment()
    ports = {
        AssessmentRepository: _FakeAssessmentRepository(assessment),
        ReportRepository: _RefusingReportRepository(),
        ReportGeneratorPortType: _UnreachableReportGenerator(),
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


class TestReadPathRefusesStaleFailedReport:
    def test_get_report_metadata_refuses_409(self, stale_row_client: TestClient) -> None:
        assessment_id = stale_row_client.state_assessment_id  # type: ignore[attr-defined]
        response = stale_row_client.get(f"/api/v1/reports/{assessment_id}")
        assert response.status_code == 409

    def test_download_report_refuses_409_not_served_from_cache(self, stale_row_client: TestClient) -> None:
        assessment_id = stale_row_client.state_assessment_id  # type: ignore[attr-defined]
        response = stale_row_client.get(f"/api/v1/reports/{assessment_id}/download")
        assert response.status_code == 409
        # The response body must not contain a PDF/HTML artifact - the
        # generic safe error body only (IllegalStateTransition's own
        # handler), never the stale cached content.
        assert b"%PDF" not in response.content
