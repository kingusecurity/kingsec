"""Phase 06: HTTP-boundary reproduction + regression for scanner failure integrity.

Two independent things proven here, per Phase 06 §4:

1. An assessment whose every attempted scanner failed, driven through the
   real production wiring (real ScannerOrchestrator + real
   AssessmentExecutionEngine + real SubmitAssessment), is retrievable via the
   real GET /api/v1/assessments/{id} route and shows status: "failed" with a
   populated failure_reason - not dependency_overrides bypassing the
   mechanism under test.
2. GET /assessments/{id}/execution/status no longer leaks a raw, unsanitized
   per-scanner error string (Phase 05 §8's confirmed, pre-existing
   disclosure) in its `error` field.

Written FIRST, before any fix, per Phase 06's ground rule #3.
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
    ScannerRequirement,
    ScannerResult,
    ScannerSurfaceTier,
    Target,
    TargetType,
)
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
                requirement=ScannerRequirement.REACHABLE_HOST,
                scan_categories=frozenset({ScanCategory.VULNERABILITY}),
                output_format=OutputFormat.FINDINGS,
                surface_tier=ScannerSurfaceTier.HOST_PORT_PATH,
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


def _run_all_failed(repo: InMemoryAssessmentRepository, engine: AssessmentExecutionEngine) -> Assessment:
    registry = InMemoryPluginRegistry()
    registry.register(_StubPlugin("nuclei", ConnectionError("refused")))
    registry.register(_StubPlugin("nmap", ConnectionError("refused")))
    orchestrator = ScannerOrchestrator(registry)

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
    return repo.get(assessment.id)


class TestAllFailedVisibleThroughRealHttpGet:
    def test_get_assessment_shows_failed_status_and_populated_reason(self) -> None:
        repo = InMemoryAssessmentRepository()
        engine = AssessmentExecutionEngine()
        assessment = _run_all_failed(repo, engine)

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
        body = resp.json()
        assert body["status"] == "failed"
        assert body["failure_reason"] is not None
        assert len(body["failure_reason"]) > 0


class TestExecutionStatusErrorFieldSanitized:
    def test_raw_exception_text_does_not_reach_execution_status_response(self) -> None:
        repo = InMemoryAssessmentRepository()
        engine = AssessmentExecutionEngine()
        unsafe = ConnectionError("Connection refused: internal-scanner.corp.local:9200")
        assessment = _run_all_failed_with_unsafe_error(repo, engine, unsafe)

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
        body = resp.json()
        raw = str(body)
        assert "internal-scanner.corp.local" not in raw
        assert "9200" not in raw
        assert "ConnectionError" not in raw


def _run_all_failed_with_unsafe_error(
    repo: InMemoryAssessmentRepository, engine: AssessmentExecutionEngine, exc: Exception
) -> Assessment:
    registry = InMemoryPluginRegistry()
    registry.register(_StubPlugin("nuclei", exc))
    orchestrator = ScannerOrchestrator(registry)

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
    return repo.get(assessment.id)
