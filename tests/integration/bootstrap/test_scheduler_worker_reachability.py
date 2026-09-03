"""KSEC-95/KSEC-98-01: does a scheduled scan's submission path reach real
assessment execution in the shipped application?

Phase 94's investigation reported that `WorkerServicePort` (implemented by
`PollingWorkerService`) is never registered in `bootstrap/composition.py`
and never constructed anywhere outside its own unit test - that finding is
untouched by Phase 98 (Section 19 explicitly does not wire or remove the
legacy worker) and is re-verified below exactly as Phase 95 left it.

What Phase 98 DID change: the scheduler no longer calls
`JobServicePort.submit_scan()` at all - it now calls
`SubmitScheduledAssessment`, which reaches the real, already-wired
`CreateAssessment` -> `SubmitAssessment` -> `ThreadJobRunner` ->
`ScannerPort` pipeline instead of the inert `scan_jobs` dead end. This is
proven below dynamically, against the REAL, fully wired application
(`create_wired_application()` - the same composition root production
uses) - not a parallel fake app, no production wiring changed to make
this test possible.

Three things are proven here, using only real components:

1. A real scheduler poll cycle against a real due schedule creates ZERO
   `scan_jobs` rows - the scheduler no longer touches that pipeline at
   all (a direct, positive regression check against Phase 95's own
   finding, now that the reachable path has changed).

2. That same poll cycle DOES create a real, persisted Assessment, correctly
   linked to the schedule occurrence that produced it.

3. `WorkerServicePort` still cannot be resolved from that same real
   container at all - `Container.resolve()` raises `BootstrapError` for
   any unregistered type - unchanged from Phase 95, since Phase 98 did
   not wire, modify, or remove the legacy worker subsystem.
"""

from __future__ import annotations

import io

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from kingsec.application import AssessmentRepository
from kingsec.application.errors import LicenseRequiredError
from kingsec.application.ports.outbound import WorkerServicePort
from kingsec.application.ports.outbound.schedule_repository import ScheduleRepositoryPort
from kingsec.application.ports.outbound.scheduler_service import SchedulerServicePort
from kingsec.application.use_cases.create_schedule import CreateSchedule
from kingsec.application.use_cases.schedule_dto import CreateScheduleRequest
from kingsec.bootstrap.application import Application
from kingsec.bootstrap.composition import create_wired_application
from kingsec.bootstrap.container import BootstrapError
from kingsec.infrastructure.persistence import create_database_engine, create_schema
from kingsec.infrastructure.persistence.models import JobModel

_TEST_FERNET_KEY = Fernet.generate_key().decode()
_TEST_JWT_SECRET = "test-jwt-secret-" + Fernet.generate_key().decode()
_TEST_PEPPER = "test-pepper-" + Fernet.generate_key().decode()


@pytest.fixture
def wired_app(tmp_path, monkeypatch) -> Application:
    """Deliberately duplicated from test_composition.py's own fixture -
    see test_route_composition_smoke.py's identical note for why this
    file does not import it instead (ruff F811 on the pytest fixture-
    reuse-via-import pattern)."""
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


class TestWorkerServicePortIsUnreachableFromRealComposition:
    def test_worker_service_port_is_not_registered_in_the_real_container(self, wired_app: Application) -> None:
        with wired_app as app:
            with pytest.raises(BootstrapError):
                app.resolve(WorkerServicePort)


class TestSchedulerReachesRealAssessmentExecutionNotTheInertJobPipeline:
    """KSEC-98-01: the positive counterpart to Phase 95's finding - the
    scheduler's real poll cycle now reaches CreateAssessment/SubmitAssessment,
    not JobServicePort.submit_scan()."""

    def test_a_real_poll_cycle_creates_zero_scan_jobs_rows_and_one_real_linked_assessment(
        self, wired_app: Application
    ) -> None:
        with wired_app as app:
            repository = app.resolve(ScheduleRepositoryPort)
            from kingsec.application.ports.outbound.audit_publisher import AuditPublisher

            audit = app.resolve(AuditPublisher)
            # license_gate=None: this test's subject is scheduled-execution
            # reachability, not CreateSchedule's own licensing - the
            # identical, already-justified pattern used in
            # test_scheduler_lifecycle.py (Phase 92) for the same reason.
            try:
                CreateSchedule(repository, audit, license_gate=None).execute(
                    CreateScheduleRequest(
                        name="Phase 98 reachability probe",
                        owner_user_id="phase-98-test",
                        target="10.0.0.55",
                        cron_expression="0 4 * * *",
                        schedule_type="cron",
                    )
                )
            except LicenseRequiredError:  # pragma: no cover - defensive, matches sibling tests
                pytest.skip("scheduling requires a paid edition in this build")

            scheduler = app.resolve(SchedulerServicePort)
            scheduler._poll_due_schedules()  # the exact method the real background thread calls

            # KSEC-98-01 regression check: the scheduler no longer touches
            # scan_jobs at all - queried directly against the real
            # database, not through any port's own read path.
            session_factory = sessionmaker(
                bind=create_engine(f"sqlite:///{app.settings.storage.data_dir / 'kingsec.db'}", future=True),
                future=True,
            )
            with session_factory() as session:
                job_rows = session.execute(select(JobModel)).scalars().all()
            assert len(job_rows) == 0, (
                "the real poll cycle must no longer create any scan_jobs row - "
                "KSEC-98-01 replaced that dead-end path entirely"
            )

            # A real, persisted, correctly-linked Assessment exists instead.
            assessments = app.resolve(AssessmentRepository)
            all_assessments = assessments.list(limit=50, offset=0)
            assert len(all_assessments) == 1, "the real poll cycle must have created exactly one real assessment"
            assessment = all_assessments[0]
            assert assessment.target.value == "10.0.0.55"
            assert assessment.owner_id == "scheduler-service"
            assert assessment.authorization is not None
            assert assessment.authorization.authorized_by == "phase-98-test"
            assert assessment.schedule_occurrence_id is not None

            # WorkerServicePort/PollingWorkerService remain untouched by
            # Phase 98 (Section 19) - still unreachable, exactly as Phase 95
            # found.
            with pytest.raises(BootstrapError):
                app.resolve(WorkerServicePort)
