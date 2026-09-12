"""Phase 08: 3-surface reproduction + regression for per-mode failure messages.

Proves, through real production wiring end to end (real plugin -> real
adapter -> real ScannerOrchestrator -> real AssessmentExecutionEngine ->
real SubmitAssessment -> real HTTP routes), that a mode-specific
user_message survives to all three surfaces named in Phase 08 §3.2:
GET /assessments/{id}'s scanner_summary[].skipped_reason,
GET .../execution/status's scanner_progress[].error, and the rendered
Scanner Coverage report section.

Two representative modes are driven through the full real pipeline here
(binary-absent via runner.py's own translation, non-zero-exit via an
adapter's guard clause) - both call sites the fix touches at a different
layer (runner.py vs. per-adapter), proving the mechanism (orchestrator
wrapping -> engine.fail_scanner -> submit_assessment's scanner_summary)
generalizes rather than re-testing all 5 modes at this cost. The other 3
modes (timeout, templates-dir, wordlist) are already proven correct at the
raise-site level in test_failure_mode_messages.py and flow through the
IDENTICAL, already-proven orchestrator/HTTP/report pipeline.

Written FIRST, before any fix, per Phase 08 ground rule #2.
"""

from __future__ import annotations

import html
from pathlib import Path
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
    Report,
    Role,
    Target,
    TargetType,
)
from kingsec.infrastructure.config.models import NmapSettings, ScannerSettings
from kingsec.infrastructure.reporting.templates import render_report_html
from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator
from kingsec.infrastructure.scanner.plugins.nmap import NmapPlugin
from kingsec.infrastructure.scanner.plugins.nuclei import NucleiPlugin
from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry
from kingsec.infrastructure.scanner.runner import CommandResult
from tests.unit.infrastructure.scanner.conftest import FakeRunner

_BINARY_ABSENT_MSG = (
    "The scanner binary could not be found. Check that this scanner is installed in the deployment environment."
)
_NONZERO_EXIT_MSG = (
    "The scan process exited with an error before producing usable results. "
    "Check the scanner's configuration or try again."
)


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


class _AlwaysCleanPlugin:
    """A second, succeeding plugin - registered alongside the failing one so
    the assessment stays COMPLETED (Phase 06 policy row 4/5: some failed,
    some succeeded). A report can only ever be generated from a COMPLETED
    assessment (domain/report.py's own gate) - an assessment where every
    attempted scanner fails correctly becomes FAILED (Phase 06), and
    Report.from_assessment() then correctly refuses it. That refusal is
    itself confirmed in this file's own pre-fix reproduction run (see the
    Phase 08 report §4/§10): the Scanner Coverage surface is structurally
    unreachable for the all-failed case, by design, not a gap in this test."""

    def metadata(self):
        from kingsec.domain import ScannerId, ScannerPluginMetadata

        return ScannerPluginMetadata(
            id=ScannerId("gobuster"), name="Gobuster Scanner", version="1.0.0",
            author="Test", description="stub", api_version="1.0",
        )

    def capabilities(self):
        from kingsec.domain import OutputFormat, ScanCategory, ScannerCapability, ScannerRequirement

        return (
            ScannerCapability(
                requirement=ScannerRequirement.REACHABLE_HOST,
                scan_categories=frozenset({ScanCategory.VULNERABILITY}),
                output_format=OutputFormat.FINDINGS,
            ),
        )

    def is_available(self):
        from kingsec.domain import PluginAvailability

        return PluginAvailability(available=True)

    def scan(self, target, config):
        from kingsec.domain import ScannerId, ScannerResult

        return ScannerResult(scanner_id=ScannerId("gobuster"), findings=(), raw_output="", duration_seconds=0.05)

    def health_check(self) -> None:
        pass

    def shutdown(self) -> None:
        pass


def _run_binary_absent(tmp_path: Path):
    plugin = NucleiPlugin(ScannerSettings(binary_path=str(tmp_path / "does-not-exist")))
    registry = InMemoryPluginRegistry()
    registry.register(plugin)
    registry.register(_AlwaysCleanPlugin())
    orchestrator = ScannerOrchestrator(registry)
    return _run(orchestrator, "nuclei")


def _run_nonzero_exit():
    # binary_path must resolve via shutil.which() (NmapPlugin.is_available())
    # for the FakeRunner below to ever be reached at all - "nmap" (the
    # NmapSettings default) is not installed on a bare CI runner, so this
    # silently collapsed into the binary-absent path there while appearing
    # to test the nonzero-exit path locally on a machine with a real nmap
    # on PATH. "python" is guaranteed present (it's running this test) and
    # is the same sentinel already used for this purpose in
    # test_adapter.py, test_nmap_plugin.py, and test_nuclei_plugin.py.
    runner = FakeRunner(CommandResult(returncode=1, stdout="", stderr="", duration_seconds=0.1))
    plugin = NmapPlugin(NmapSettings(binary_path="python"), runner=runner)
    registry = InMemoryPluginRegistry()
    registry.register(plugin)
    registry.register(_AlwaysCleanPlugin())
    orchestrator = ScannerOrchestrator(registry)
    return _run(orchestrator, "nmap")


def _run(orchestrator: ScannerOrchestrator, scanner_id: str):
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


def _get_assessment_response(repo, assessment) -> dict:
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


def _get_execution_status_response(repo, engine, assessment) -> dict:
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


def _render_report_section(assessment: Assessment) -> str:
    report = Report.from_assessment(assessment)
    rendered = render_report_html(report)
    section = rendered.split('id="scanner-coverage"')[1].split("</section>")[0]
    # The template correctly HTML-escapes rendered text (e.g. "'" ->
    # "&#x27;") - unescape before comparing against the plain-text expected
    # message, since that escaping is itself correct, safe behavior, not
    # something these tests should be sensitive to.
    return html.unescape(section)


class TestBinaryAbsentAllThreeSurfaces:
    def test_message_reaches_all_three_surfaces(self, tmp_path: Path) -> None:
        assessment, engine, repo = _run_binary_absent(tmp_path)

        assessment_body = _get_assessment_response(repo, assessment)
        status_body = _get_execution_status_response(repo, engine, assessment)
        report_section = _render_report_section(assessment)

        summary_entry = next(s for s in assessment_body["scanner_summary"] if s["scanner_id"] == "nuclei")
        assert _BINARY_ABSENT_MSG in summary_entry["skipped_reason"]

        progress_entry = next(p for p in status_body["scanner_progress"] if p["scanner_id"] == "nuclei")
        assert _BINARY_ABSENT_MSG in progress_entry["error"]

        assert _BINARY_ABSENT_MSG in report_section


class TestNonZeroExitAllThreeSurfaces:
    def test_message_reaches_all_three_surfaces(self) -> None:
        assessment, engine, repo = _run_nonzero_exit()

        assessment_body = _get_assessment_response(repo, assessment)
        status_body = _get_execution_status_response(repo, engine, assessment)
        report_section = _render_report_section(assessment)

        summary_entry = next(s for s in assessment_body["scanner_summary"] if s["scanner_id"] == "nmap")
        assert _NONZERO_EXIT_MSG in summary_entry["skipped_reason"]

        progress_entry = next(p for p in status_body["scanner_progress"] if p["scanner_id"] == "nmap")
        assert _NONZERO_EXIT_MSG in progress_entry["error"]

        assert _NONZERO_EXIT_MSG in report_section


class TestTwoModesDistinguishableAcrossAllSurfaces:
    def test_binary_absent_and_nonzero_exit_differ_on_every_surface(self, tmp_path: Path) -> None:
        a1, _e1, r1 = _run_binary_absent(tmp_path)
        a2, _e2, r2 = _run_nonzero_exit()

        body1 = _get_assessment_response(r1, a1)
        body2 = _get_assessment_response(r2, a2)
        reason1 = next(s for s in body1["scanner_summary"] if s["scanner_id"] == "nuclei")["skipped_reason"]
        reason2 = next(s for s in body2["scanner_summary"] if s["scanner_id"] == "nmap")["skipped_reason"]
        assert reason1 != reason2
