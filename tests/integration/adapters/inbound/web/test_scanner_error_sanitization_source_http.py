"""Phase 07: HTTP-boundary reproduction + regression for source-level scanner
error sanitization.

Proves, through the real HTTP boundary (not dependency_overrides bypassing
the mechanism under test), that:

1. An unvetted OS-level exception's raw text reaches NEITHER
   GET /assessments/{id}'s scanner_summary[].skipped_reason NOR
   GET /assessments/{id}/execution/status's scanner_progress[].error.
2. A developer-authored KingSecError's useful, safe message SURVIVES to both
   surfaces - the test that distinguishes this phase's fix from Phase 06
   §3.3's blanket collapse.
3. Phase 06's all-failed -> FAILED behavior still holds, with failure_reason
   still containing scanner names and no raw text.

Written FIRST, before any fix, per Phase 07's ground rule #2.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user, require_viewer
from kingsec.adapters.inbound.web.dependencies import get_service
from kingsec.application.assessment_execution import AssessmentExecutionEngine
from kingsec.application.dto import SubmitAssessmentRequest
from kingsec.application.ports.inbound.service_api import ServiceAPI
from kingsec.application.submit_assessment import SubmitAssessment
from kingsec.application.use_cases.get_assessment import GetAssessment
from kingsec.domain import (
    Assessment,
    Authorization,
    OutputFormat,
    PluginAvailability,
    PluginConfig,
    Role,
    ScanCategory,
    ScannerCapability,
    ScannerId,
    ScannerPluginMetadata,
    ScannerResult,
    Target,
    TargetType,
)
from kingsec.infrastructure.scanner.errors import ScannerExecutionError
from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry


class _StubPlugin:
    def __init__(self, plugin_id: str, raise_on_scan: Exception) -> None:
        self._id = plugin_id
        self._raise_on_scan = raise_on_scan

    def metadata(self) -> ScannerPluginMetadata:
        return ScannerPluginMetadata(
            id=ScannerId(self._id),
            name=f"{self._id.title()} Scanner",
            version="1.0.0",
            author="Test",
            description="stub",
            api_version="1.0",
        )

    def capabilities(self) -> tuple[ScannerCapability, ...]:
        return (
            ScannerCapability(
                target_types=frozenset({TargetType.IP_ADDRESS}),
                scan_categories=frozenset({ScanCategory.VULNERABILITY}),
                output_format=OutputFormat.FINDINGS,
            ),
        )

    def is_available(self) -> PluginAvailability:
        return PluginAvailability(available=True)

    def scan(self, target: Target, config: PluginConfig) -> ScannerResult:
        raise self._raise_on_scan

    def health_check(self) -> None:
        pass

    def shutdown(self) -> None:
        pass


class InMemoryAssessmentRepository:
    def __init__(self) -> None:
        self._store: dict[str, Assessment] = {}

    def save(self, assessment: Assessment) -> None:
        self._store[assessment.id.value] = assessment

    def get(self, assessment_id: Any) -> Assessment:
        return self._store[assessment_id.value]

    def list(self, *, limit: int = 50, offset: int = 0) -> list[Assessment]:
        return list(self._store.values())[offset : offset + limit]

    def delete(self, assessment_id: Any) -> None:
        del self._store[assessment_id.value]


class _InlineJobRunner:
    def submit(self, job_id: str, fn: Any, *args: Any, **kwargs: Any) -> None:
        fn()

    def is_running(self, job_id: str) -> bool:
        return False

    def shutdown(self, wait: bool = True) -> None:
        pass


class _GetOnlyService(ServiceAPI):
    def __init__(self, get_use_case: GetAssessment) -> None:
        self._get = get_use_case

    def get_assessment(self, request):
        return self._get.execute(request)

    def create_assessment(self, request): raise NotImplementedError
    def start_assessment(self, request): raise NotImplementedError
    def submit_assessment(self, request): raise NotImplementedError
    def cancel_assessment(self, request): raise NotImplementedError
    def list_assessments(self, request): raise NotImplementedError
    def generate_report(self, request): raise NotImplementedError
    def delete_assessment(self, request): raise NotImplementedError


def _user(user_id: str, role: Role = Role.VIEWER) -> CurrentUser:
    return CurrentUser(user_id=user_id, username=user_id, role=role)


def _run(exc: Exception) -> tuple[Assessment, AssessmentExecutionEngine, InMemoryAssessmentRepository]:
    registry = InMemoryPluginRegistry()
    registry.register(_StubPlugin("nuclei", exc))
    orchestrator = ScannerOrchestrator(registry)

    repo = InMemoryAssessmentRepository()
    engine = AssessmentExecutionEngine()

    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessment.set_ownership("alice")
    repo.save(assessment)

    use_case = SubmitAssessment(
        assessments=repo,
        scanner=orchestrator,
        job_runner=_InlineJobRunner(),
        execution_engine=engine,
        scanner_executor=orchestrator,
    )
    use_case.execute(SubmitAssessmentRequest(str(assessment.id), requesting_user="alice", is_admin=False))
    return repo.get(assessment.id), engine, repo


def _get_assessment_response(repo: InMemoryAssessmentRepository, assessment: Assessment) -> dict:
    app = FastAPI()
    service = _GetOnlyService(GetAssessment(repo))
    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router

    register_error_handlers(app)
    app.include_router(router)
    app.dependency_overrides[get_service] = lambda: service
    app.dependency_overrides[get_current_user] = lambda: _user("alice")
    app.dependency_overrides[require_viewer] = lambda: _user("alice")

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get(f"/api/v1/assessments/{assessment.id}")
    assert resp.status_code == 200
    return resp.json()


def _get_execution_status_response(repo: InMemoryAssessmentRepository, engine: AssessmentExecutionEngine, assessment: Assessment) -> dict:
    app = FastAPI()

    class _StubApp:
        def resolve(self, port_type: type) -> Any:
            if port_type is AssessmentExecutionEngine:
                return engine
            return repo

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]
    from kingsec.adapters.inbound.web.execution_routes import router as execution_router

    app.include_router(execution_router)
    app.dependency_overrides[get_current_user] = lambda: _user("alice")
    app.dependency_overrides[require_viewer] = lambda: _user("alice")

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get(f"/api/v1/assessments/{assessment.id}/execution/status")
    assert resp.status_code == 200
    return resp.json()


class TestUnvettedFailureLeaksNowhere:
    def test_neither_endpoint_shows_raw_text(self) -> None:
        assessment, engine, repo = _run(ConnectionError("Connection refused: internal-scanner.corp.local:9200"))

        assessment_body = _get_assessment_response(repo, assessment)
        status_body = _get_execution_status_response(repo, engine, assessment)

        assessment_raw = str(assessment_body)
        status_raw = str(status_body)
        for raw in (assessment_raw, status_raw):
            assert "internal-scanner.corp.local" not in raw
            assert "9200" not in raw
            assert "ConnectionError" not in raw


class TestDeveloperAuthoredFailureSurvives:
    def test_useful_message_reaches_both_surfaces(self) -> None:
        # ScannerExecutionError is what a real adapter raises for a genuine,
        # explainable failure (e.g. a non-zero exit) - a KingSecError whose
        # user_message is meant to be shown.
        exc = ScannerExecutionError("nuclei exited with code 1", context={"returncode": 1})
        assessment, engine, repo = _run(exc)

        assessment_body = _get_assessment_response(repo, assessment)
        status_body = _get_execution_status_response(repo, engine, assessment)

        expected = "The security scan could not be completed."
        summary_entry = next(s for s in assessment_body["scanner_summary"] if s["scanner_id"] == "nuclei")
        assert summary_entry["skipped_reason"] is not None
        assert expected in summary_entry["skipped_reason"]

        progress_entry = next(p for p in status_body["scanner_progress"] if p["scanner_id"] == "nuclei")
        assert progress_entry["error"] is not None
        assert expected in progress_entry["error"]


class TestAllFailedBehaviorStillHolds:
    def test_status_failed_reason_has_names_no_raw_text(self) -> None:
        assessment, _engine, repo = _run(ConnectionError("Connection refused: internal-scanner.corp.local:9200"))
        body = _get_assessment_response(repo, assessment)

        assert body["status"] == "failed"
        assert body["failure_reason"] is not None
        assert "Nuclei" in body["failure_reason"]
        assert "internal-scanner.corp.local" not in body["failure_reason"]
