"""KSEC-92-07/08/09: prove the scheduler is wired into the REAL application
lifecycle, not merely that InProcessScheduler's own start()/stop() work in
isolation - that is already covered elsewhere and proves nothing about
composition.

Phase 91 (KSEC-91-02) found that InProcessScheduler was fully built and
unit-tested but never actually started by any shipped entry point -
scheduled scans were configured but never triggered. Phase 92 wires
`SchedulerServicePort` resolve+start()/stop() into `create_fastapi_app()`'s
own FastAPI `lifespan` (see app.py's `_scheduler_lifespan` for the full
design rationale: why lifespan rather than `Application.start()`/`.stop()`,
why no settings flag, why it fails closed).

These tests use the REAL `create_wired_application()` (via a locally
duplicated `wired_app` fixture - see test_route_composition_smoke.py's own
identical duplication note for why it is not imported instead) and the
REAL `create_fastapi_app()`. The only test double is `JobServicePort`,
substituted via the real DI container (the exact technique
test_schedule_repository.py's `TestSchedulerTickRace` already established)
so the deterministic execution-path test (KSEC-92-08) has a synchronization
point to wait on instead of a real scan actually running - no network
contact, no real scanner invocation, no external service, no sleep-based
timing.
"""

from __future__ import annotations

import io
import threading

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from kingsec.application.jobs import InMemoryJobService, ScanJob, ScanJobResult
from kingsec.application.ports.job_service import JobServicePort
from kingsec.application.ports.outbound.audit_publisher import AuditPublisher
from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort
from kingsec.application.ports.outbound.scheduler_service import SchedulerServicePort
from kingsec.application.use_cases.create_schedule import CreateSchedule
from kingsec.application.use_cases.schedule_dto import CreateScheduleRequest
from kingsec.bootstrap.application import Application
from kingsec.bootstrap.composition import create_wired_application
from kingsec.infrastructure.persistence import create_database_engine, create_schema

_TEST_FERNET_KEY = Fernet.generate_key().decode()
_TEST_JWT_SECRET = "test-jwt-secret-" + Fernet.generate_key().decode()
_TEST_PEPPER = "test-pepper-" + Fernet.generate_key().decode()


@pytest.fixture
def wired_app(tmp_path, monkeypatch) -> Application:
    """Deliberately duplicated from test_composition.py's own fixture -
    see test_route_composition_smoke.py's identical note for why."""
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


class _SignalingJobService(JobServicePort):
    """Wraps the real InMemoryJobService, signaling an Event the instant
    submit_scan() is actually called - the deterministic boundary
    KSEC-92-08 asks for, distinguishing "the scheduler thread started"
    from "the scheduled execution path was actually reached." Still a
    real, working JobServicePort (delegates every method for real, not
    a bare mock that only records a call) - every non-submit_scan method
    is an explicit one-line delegation because ABCMeta requires abstract
    methods to be literally present in the class body; a __getattr__
    fallback does not satisfy that at instantiation time."""

    def __init__(self) -> None:
        self._inner = InMemoryJobService()
        self.submitted_event = threading.Event()
        self.submitted_target: str | None = None

    def submit_scan(self, target: str, config: dict[str, object] | None = None) -> ScanJob:
        self.submitted_target = target
        job = self._inner.submit_scan(target, config)
        self.submitted_event.set()
        return job

    def get_job(self, job_id: str) -> ScanJob:
        return self._inner.get_job(job_id)

    def list_jobs(self) -> list[ScanJob]:
        return self._inner.list_jobs()

    def cancel_job(self, job_id: str) -> ScanJob:
        return self._inner.cancel_job(job_id)

    def get_job_result(self, job_id: str) -> ScanJobResult:
        return self._inner.get_job_result(job_id)

    def transition_job(self, job_id: str, target_status: str) -> ScanJob:
        return self._inner.transition_job(job_id, target_status)

    def find_oldest_pending(self) -> ScanJob | None:
        return self._inner.find_oldest_pending()


class TestSchedulerResolvedThroughRealLifecycle:
    """KSEC-92-07: application startup -> scheduler resolved through the
    real DI container -> start() invoked through the lifecycle -> becomes
    active -> shutdown invokes stop() -> terminates cleanly. Uses
    `with TestClient(app) as client:` specifically because that is the
    one style that DOES drive FastAPI's lifespan (confirmed empirically
    during this phase's investigation) - every other test in this
    repository uses the plain, non-context-manager style precisely so it
    does NOT trigger this."""

    def test_scheduler_starts_on_app_startup_and_stops_on_shutdown(self, wired_app: Application) -> None:
        from kingsec.adapters.inbound.web.app import create_fastapi_app

        with wired_app as app:
            scheduler = app.resolve(SchedulerServicePort)
            assert scheduler.is_running() is False, "must not be running before the app is ever served"

            fastapi_app = create_fastapi_app(app)
            with TestClient(fastapi_app) as client:
                assert scheduler.is_running() is True, "lifespan startup must have started it"
                resp = client.get("/api/v1/healthz/live")
                assert resp.status_code == 200

            assert scheduler.is_running() is False, "lifespan shutdown must have stopped it"

    def test_resolving_the_scheduler_before_and_after_serving_returns_the_same_instance(
        self, wired_app: Application
    ) -> None:
        """Proves this is genuinely the DI container's own singleton-via-
        factory instance being started/stopped - not a second, parallel
        scheduler the smoke test accidentally created."""
        from kingsec.adapters.inbound.web.app import create_fastapi_app

        with wired_app as app:
            before = app.resolve(SchedulerServicePort)
            fastapi_app = create_fastapi_app(app)
            with TestClient(fastapi_app):
                during = app.resolve(SchedulerServicePort)
            assert before is during


class TestScheduledExecutionPathIsReachable:
    """KSEC-92-08: application lifecycle -> scheduler -> find_due() ->
    job submission boundary, proven with real (not sleep-timed) data."""

    def test_a_due_schedule_is_actually_submitted_through_the_real_lifecycle(self, wired_app: Application) -> None:
        from kingsec.adapters.inbound.web.app import create_fastapi_app

        with wired_app as app:
            # A freshly-created schedule has next_run=None, enabled=True,
            # paused=False - ScanSchedule.is_due() treats that as
            # immediately due, so the scheduler's very first poll cycle
            # (which runs immediately on start(), before its first
            # 60-second wait) should reach it with no artificial delay.
            #
            # CreateSchedule is constructed here directly (not resolved
            # from the container) with license_gate=None, bypassing the
            # real app's community-edition licensing check - this test's
            # subject is the scheduler's lifecycle wiring, not
            # CreateSchedule's own authorization, which has its own
            # dedicated coverage elsewhere. The repository and audit
            # publisher are still the real, DI-resolved instances the
            # scheduler itself will read from via find_due().
            repository = app.resolve(ScheduleRepositoryPort)
            audit = app.resolve(AuditPublisher)
            create_schedule = CreateSchedule(repository, audit, license_gate=None)
            create_schedule.execute(
                CreateScheduleRequest(
                    name="Phase 92 lifecycle probe",
                    owner_user_id="phase-92-test",
                    target="10.0.0.99",
                    cron_expression="0 3 * * *",
                    schedule_type="cron",
                )
            )

            signaling_jobs = _SignalingJobService()
            app.container.register_instance(JobServicePort, signaling_jobs)

            fastapi_app = create_fastapi_app(app)
            with TestClient(fastapi_app):
                reached = signaling_jobs.submitted_event.wait(timeout=10)

            assert reached, (
                "the scheduler's real poll cycle never reached submit_scan() within 10s - "
                "either the scheduler never actually started, or find_due()/the poll loop "
                "never ran the job-submission boundary"
            )
            assert signaling_jobs.submitted_target == "10.0.0.99"


class TestSchedulerStartStopSafety:
    """KSEC-92-09: duplicate start()/stop() cannot happen through the real
    lifecycle path (only one lifespan startup/shutdown per served app
    lifetime), but this proves InProcessScheduler's own guards hold even
    when driven directly, matching what the lifespan relies on."""

    def test_start_twice_does_not_create_a_second_thread(self, wired_app: Application) -> None:
        with wired_app as app:
            scheduler = app.resolve(SchedulerServicePort)
            scheduler.start()
            first_thread = scheduler._thread
            scheduler.start()
            second_thread = scheduler._thread
            assert first_thread is second_thread, "a second start() must not replace the running thread"
            scheduler.stop()

    def test_stop_twice_does_not_raise(self, wired_app: Application) -> None:
        with wired_app as app:
            scheduler = app.resolve(SchedulerServicePort)
            scheduler.start()
            scheduler.stop()
            scheduler.stop()  # must be a safe no-op, not an exception

    def test_stop_without_ever_starting_does_not_raise(self, wired_app: Application) -> None:
        with wired_app as app:
            scheduler = app.resolve(SchedulerServicePort)
            scheduler.stop()

    def test_start_after_stop_creates_a_fresh_working_thread(self, wired_app: Application) -> None:
        with wired_app as app:
            scheduler = app.resolve(SchedulerServicePort)
            scheduler.start()
            scheduler.stop()
            assert scheduler.is_running() is False
            scheduler.start()
            assert scheduler.is_running() is True
            scheduler.stop()

    def test_a_failing_lifespan_component_after_startup_still_stops_the_scheduler(
        self, wired_app: Application
    ) -> None:
        """KSEC-92-06: if scheduler.start() succeeds and something later
        raises inside the served app's lifetime, stop() must still run -
        proven directly against the lifespan context manager itself
        (the smallest unit that owns this guarantee), not the whole
        served app, since forcing a mid-request failure through a real
        server is unnecessary to prove the finally-based cleanup works."""
        import asyncio

        from kingsec.adapters.inbound.web.app import _scheduler_lifespan

        async def _drive() -> None:
            scheduler = app.resolve(SchedulerServicePort)
            with pytest.raises(RuntimeError):
                async with _scheduler_lifespan(app):
                    assert scheduler.is_running() is True
                    raise RuntimeError("simulated failure elsewhere in the served app's lifetime")
            assert scheduler.is_running() is False, "stop() must still have run despite the exception"

        with wired_app as app:
            asyncio.run(_drive())
