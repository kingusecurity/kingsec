"""KSEC-95: does a scheduled scan's job-submission path reach real
assessment execution in the shipped application?

Phase 94's investigation reported that `WorkerServicePort` (implemented by
`PollingWorkerService`) is never registered in `bootstrap/composition.py`
and never constructed anywhere outside its own unit test. That claim was
established by static repository search. This test corroborates it
dynamically, against the REAL, fully wired application
(`create_wired_application()` - the same composition root production
uses) - not a parallel fake app, no production wiring changed to make
this test possible.

Two things are proven here, using only real components:

1. A real scheduler poll cycle against a real due schedule DOES create a
   real, persisted `scan_jobs` row (Stage A: "job row created" - see the
   Phase 95 report's stage taxonomy) - `PersistentJobService` and
   `SqlAlchemyScheduleRepository` are both real, resolved from the real
   DI container, exactly as production wires them.

2. `WorkerServicePort` cannot be resolved from that same real container
   at all - `Container.resolve()` raises `BootstrapError` for any
   unregistered type - proving nothing in the real composition graph is
   capable of ever picking up the row created in (1) (Stage B: "worker
   picks up job" is unreachable, not merely "not yet started").

No fake scanner or worker is introduced. No production wiring is
modified to make this test pass - if `WorkerServicePort` were registered
in a future phase, this test would need updating (and should fail loudly
until it is), which is the intended, honest behavior of a reachability
proof rather than a behavior mock.
"""

from __future__ import annotations

import io

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from kingsec.application.errors import LicenseRequiredError
from kingsec.application.ports.job_service import JobServicePort
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


class TestSchedulerJobSubmissionReachesRealPersistenceOnly:
    def test_a_real_poll_cycle_creates_a_real_persisted_job_row_with_no_reachable_consumer(
        self, wired_app: Application
    ) -> None:
        with wired_app as app:
            repository = app.resolve(ScheduleRepositoryPort)
            from kingsec.application.ports.outbound.audit_publisher import AuditPublisher

            audit = app.resolve(AuditPublisher)
            # license_gate=None: this test's subject is job-submission
            # reachability, not CreateSchedule's own licensing - the
            # identical, already-justified pattern used in
            # test_scheduler_lifecycle.py (Phase 92) for the same reason.
            try:
                CreateSchedule(repository, audit, license_gate=None).execute(
                    CreateScheduleRequest(
                        name="Phase 95 reachability probe",
                        owner_user_id="phase-95-test",
                        target="10.0.0.55",
                        cron_expression="0 4 * * *",
                        schedule_type="cron",
                    )
                )
            except LicenseRequiredError:  # pragma: no cover - defensive, matches sibling tests
                pytest.skip("scheduling requires a paid edition in this build")

            scheduler = app.resolve(SchedulerServicePort)
            scheduler._poll_due_schedules()  # the exact method the real background thread calls

            # Stage A: a real, persisted job row exists - queried directly
            # against the real database, not through JobServicePort's own
            # (config-dropping) read path, to see exactly what production
            # actually wrote.
            job_service = app.resolve(JobServicePort)
            assert job_service is not None  # confirms this port IS real and registered

            session_factory = sessionmaker(
                bind=create_engine(f"sqlite:///{app.settings.storage.data_dir / 'kingsec.db'}", future=True),
                future=True,
            )
            with session_factory() as session:
                rows = session.execute(select(JobModel)).scalars().all()
            assert len(rows) == 1, "the real poll cycle must have created exactly one persisted scan_jobs row"
            assert rows[0].target == "10.0.0.55"
            assert rows[0].status == "PENDING", "nothing ever transitions it further - no registered consumer exists"

            # Stage B: nothing in the real composition graph can ever pick
            # this row up - proven, not assumed.
            with pytest.raises(BootstrapError):
                app.resolve(WorkerServicePort)
