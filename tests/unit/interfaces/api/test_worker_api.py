from __future__ import annotations

from fastapi.testclient import TestClient

from kingsec.application.jobs import InMemoryJobService
from kingsec.infrastructure.worker.polling_worker import PollingWorkerService
from kingsec.interfaces.api.app import create_app

from .helpers import fake_get_current_user

_WORKER = PollingWorkerService(job_service=InMemoryJobService())
_APP = create_app(worker_service=_WORKER, get_current_user=fake_get_current_user)
_EMPTY_APP = create_app()


class TestWorkerStart:
    def setup_method(self) -> None:
        self.client = TestClient(_APP)

    def test_start_returns_200(self) -> None:
        response = self.client.post("/worker/start")
        assert response.status_code == 200
        assert response.json()["status"] == "worker_started"

    def test_start_is_idempotent(self) -> None:
        self.client.post("/worker/start")
        response = self.client.post("/worker/start")
        assert response.status_code == 200


class TestWorkerStop:
    def setup_method(self) -> None:
        self.client = TestClient(_APP)

    def test_stop_returns_200(self) -> None:
        self.client.post("/worker/start")
        response = self.client.post("/worker/stop")
        assert response.status_code == 200
        assert response.json()["status"] == "worker_stopped"


class TestWorkerExecute:
    def setup_method(self) -> None:
        self.job_service = InMemoryJobService()
        self.worker = PollingWorkerService(job_service=self.job_service)
        self.app = create_app(worker_service=self.worker, get_current_user=fake_get_current_user)
        self.client = TestClient(self.app)

    def test_execute_no_pending_returns_404(self) -> None:
        response = self.client.post("/worker/execute")
        assert response.status_code == 404

    def test_execute_pending_job_returns_200(self) -> None:
        self.job_service.submit_scan(target="example.com")
        response = self.client.post("/worker/execute")
        assert response.status_code == 200
        data = response.json()
        assert "job_id" in data


class TestWorkerStatus:
    def setup_method(self) -> None:
        self.client = TestClient(_APP)

    def test_status_returns_stopped(self) -> None:
        response = self.client.get("/worker/status")
        assert response.status_code == 200
        assert response.json()["status"] == "stopped"

    def test_status_returns_running(self) -> None:
        self.client.post("/worker/start")
        response = self.client.get("/worker/status")
        assert response.status_code == 200
        assert response.json()["status"] == "running"


class TestWorkerHeartbeat:
    def setup_method(self) -> None:
        self.client = TestClient(_APP)

    def test_heartbeat_returns_200(self) -> None:
        response = self.client.get("/worker/heartbeat")
        assert response.status_code == 200

    def test_heartbeat_contains_expected_keys(self) -> None:
        response = self.client.get("/worker/heartbeat")
        data = response.json()
        assert "worker_id" in data
        assert "status" in data
        assert "timestamp" in data
        assert "current_job_id" in data
        assert "jobs_completed" in data
        assert "jobs_failed" in data


class TestOpenAPI:
    def setup_method(self) -> None:
        self.client = TestClient(_APP)

    def test_worker_paths_in_openapi(self) -> None:
        schema = self.client.get("/openapi.json").json()
        paths = schema["paths"]
        assert "/worker/start" in paths
        assert "/worker/stop" in paths
        assert "/worker/execute" in paths
        assert "/worker/status" in paths
        assert "/worker/heartbeat" in paths

    def test_no_worker_service_no_worker_routes(self) -> None:
        client = TestClient(_EMPTY_APP)
        schema = client.get("/openapi.json").json()
        assert "/worker/start" not in schema["paths"]
