from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kingsec.application.jobs import (
    InMemoryJobService,
    JobStatus,
    ScanJobResult,
)
from kingsec.interfaces.api.app import create_app

from .helpers import fake_get_current_user

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_JOB_SERVICE = InMemoryJobService()
_APP = create_app(job_service=_JOB_SERVICE, get_current_user=fake_get_current_user)
_EMPTY_APP = create_app()


def _prime_job(status: JobStatus = JobStatus.COMPLETED) -> str:
    """Submit a scan job and optionally run it to *status*."""
    service = _JOB_SERVICE
    job = service.submit_scan(target="primed.example.com")
    if status is JobStatus.PENDING:
        return job.id.value
    service.transition_job(job.id.value, JobStatus.RUNNING)
    if status is JobStatus.RUNNING:
        return job.id.value
    if status is JobStatus.FAILED:
        service.transition_job(job.id.value, JobStatus.FAILED)
        return job.id.value
    if status is JobStatus.CANCELLED:
        service.cancel_job(job.id.value)
        return job.id.value
    service.transition_job(job.id.value, JobStatus.COMPLETED)
    result = ScanJobResult(
        job_id=job.id.value,
        completed_at=datetime.now(UTC),
        findings=({"port": 443, "status": "open"},),
    )
    service.store_result(job.id.value, result)
    return job.id.value


def _reset_service() -> None:
    _JOB_SERVICE._jobs.clear()
    _JOB_SERVICE._results.clear()


# ===========================================================================
# POST /jobs
# ===========================================================================


class TestCreateJob:
    def setup_method(self) -> None:
        _reset_service()
        self.client = TestClient(_APP)

    def test_create_returns_202(self) -> None:
        response = self.client.post("/jobs", json={"target": "example.com"})
        assert response.status_code == 202

    def test_create_returns_job_response(self) -> None:
        response = self.client.post("/jobs", json={"target": "example.com"})
        data = response.json()
        assert "job_id" in data
        assert data["status"] == "PENDING"
        assert data["target"] == "example.com"
        assert "created_at" in data

    def test_create_with_config(self) -> None:
        response = self.client.post(
            "/jobs",
            json={"target": "example.com", "config": {"scanners": ["nuclei"]}},
        )
        assert response.status_code == 202
        data = response.json()
        assert data["config"] == {"scanners": ["nuclei"]}

    def test_create_missing_target_returns_422(self) -> None:
        response = self.client.post("/jobs", json={})
        assert response.status_code == 422

    def test_create_empty_target_returns_422(self) -> None:
        response = self.client.post("/jobs", json={"target": ""})
        assert response.status_code == 422

    def test_create_non_string_target_returns_422(self) -> None:
        response = self.client.post("/jobs", json={"target": 42})
        assert response.status_code == 422

    def test_create_invalid_config_returns_422(self) -> None:
        response = self.client.post("/jobs", json={"target": "example.com", "config": "not-a-dict"})
        assert response.status_code == 422


# ===========================================================================
# GET /jobs
# ===========================================================================


class TestListJobs:
    def setup_method(self) -> None:
        _reset_service()
        self.client = TestClient(_APP)

    def test_list_returns_200(self) -> None:
        response = self.client.get("/jobs")
        assert response.status_code == 200

    def test_list_empty(self) -> None:
        response = self.client.get("/jobs")
        assert response.json() == []

    def test_list_returns_jobs(self) -> None:
        _prime_job(JobStatus.PENDING)
        _prime_job(JobStatus.PENDING)
        response = self.client.get("/jobs")
        data = response.json()
        assert len(data) == 2
        for entry in data:
            assert "job_id" in entry
            assert "status" in entry
            assert "target" in entry


# ===========================================================================
# GET /jobs/{job_id}
# ===========================================================================


class TestGetJob:
    def setup_method(self) -> None:
        _reset_service()
        self.client = TestClient(_APP)

    def test_get_returns_200(self) -> None:
        jid = _prime_job(JobStatus.COMPLETED)
        response = self.client.get(f"/jobs/{jid}")
        assert response.status_code == 200

    def test_get_returns_job_details(self) -> None:
        jid = _prime_job(JobStatus.PENDING)
        response = self.client.get(f"/jobs/{jid}")
        data = response.json()
        assert data["job_id"] == jid
        assert data["target"] == "primed.example.com"
        assert data["status"] == "PENDING"

    def test_get_nonexistent_returns_404(self) -> None:
        response = self.client.get("/jobs/no-such-job")
        assert response.status_code == 404

    def test_get_with_invalid_id_returns_404(self) -> None:
        response = self.client.get("/jobs/00000000-0000-0000-0000-000000000000")
        assert response.status_code == 404


# ===========================================================================
# DELETE /jobs/{job_id}
# ===========================================================================


class TestCancelJob:
    def setup_method(self) -> None:
        _reset_service()
        self.client = TestClient(_APP)

    def test_cancel_pending_returns_200(self) -> None:
        jid = _prime_job(JobStatus.PENDING)
        response = self.client.delete(f"/jobs/{jid}")
        assert response.status_code == 200
        assert response.json()["status"] == "CANCELLED"

    def test_cancel_running_returns_200(self) -> None:
        jid = _prime_job(JobStatus.RUNNING)
        response = self.client.delete(f"/jobs/{jid}")
        assert response.status_code == 200

    def test_cancel_nonexistent_returns_404(self) -> None:
        response = self.client.delete("/jobs/no-such-job")
        assert response.status_code == 404

    def test_cancel_completed_returns_409(self) -> None:
        jid = _prime_job(JobStatus.COMPLETED)
        response = self.client.delete(f"/jobs/{jid}")
        assert response.status_code == 409

    def test_cancel_failed_returns_409(self) -> None:
        jid = _prime_job(JobStatus.FAILED)
        response = self.client.delete(f"/jobs/{jid}")
        assert response.status_code == 409

    def test_cancel_already_cancelled_returns_409(self) -> None:
        jid = _prime_job(JobStatus.PENDING)
        self.client.delete(f"/jobs/{jid}")
        response = self.client.delete(f"/jobs/{jid}")
        assert response.status_code == 409

    def test_cancel_updates_status(self) -> None:
        jid = _prime_job(JobStatus.PENDING)
        response = self.client.delete(f"/jobs/{jid}")
        data = response.json()
        assert data["status"] == "CANCELLED"
        assert data["job_id"] == jid


# ===========================================================================
# GET /jobs/{job_id}/result
# ===========================================================================


class TestGetJobResult:
    def setup_method(self) -> None:
        _reset_service()
        self.client = TestClient(_APP)

    def test_get_result_completed_returns_200(self) -> None:
        jid = _prime_job(JobStatus.COMPLETED)
        response = self.client.get(f"/jobs/{jid}/result")
        assert response.status_code == 200

    def test_get_result_contains_findings(self) -> None:
        jid = _prime_job(JobStatus.COMPLETED)
        response = self.client.get(f"/jobs/{jid}/result")
        data = response.json()
        assert data["job_id"] == jid
        assert len(data["findings"]) == 1
        assert data["findings"][0]["port"] == 443
        assert "completed_at" in data

    def test_get_result_pending_returns_409(self) -> None:
        jid = _prime_job(JobStatus.PENDING)
        response = self.client.get(f"/jobs/{jid}/result")
        assert response.status_code == 409

    def test_get_result_running_returns_409(self) -> None:
        jid = _prime_job(JobStatus.RUNNING)
        response = self.client.get(f"/jobs/{jid}/result")
        assert response.status_code == 409

    def test_get_result_failed_returns_409(self) -> None:
        jid = _prime_job(JobStatus.FAILED)
        response = self.client.get(f"/jobs/{jid}/result")
        assert response.status_code == 409

    def test_get_result_cancelled_returns_409(self) -> None:
        jid = _prime_job(JobStatus.CANCELLED)
        response = self.client.get(f"/jobs/{jid}/result")
        assert response.status_code == 409

    def test_get_result_nonexistent_returns_404(self) -> None:
        response = self.client.get("/jobs/no-such-job/result")
        assert response.status_code == 404


# ===========================================================================
# OpenAPI schema
# ===========================================================================


class TestOpenAPI:
    def setup_method(self) -> None:
        _reset_service()
        self.client = TestClient(_APP)

    def test_jobs_path_in_openapi(self) -> None:
        schema = self.client.get("/openapi.json").json()
        paths = schema["paths"]
        assert "/jobs" in paths
        assert "/jobs/{job_id}" in paths
        assert "/jobs/{job_id}/result" in paths

    def test_post_jobs_in_openapi(self) -> None:
        schema = self.client.get("/openapi.json").json()
        assert "post" in schema["paths"]["/jobs"]

    def test_get_jobs_in_openapi(self) -> None:
        schema = self.client.get("/openapi.json").json()
        assert "get" in schema["paths"]["/jobs"]

    def test_get_job_by_id_in_openapi(self) -> None:
        schema = self.client.get("/openapi.json").json()
        assert "get" in schema["paths"]["/jobs/{job_id}"]

    def test_delete_job_in_openapi(self) -> None:
        schema = self.client.get("/openapi.json").json()
        assert "delete" in schema["paths"]["/jobs/{job_id}"]

    def test_get_job_result_in_openapi(self) -> None:
        schema = self.client.get("/openapi.json").json()
        assert "get" in schema["paths"]["/jobs/{job_id}/result"]


# ===========================================================================
# Dependency injection
# ===========================================================================


class TestDependencyInjection:
    def test_no_job_service_no_jobs_routes(self) -> None:
        client = TestClient(_EMPTY_APP)
        schema = client.get("/openapi.json").json()
        assert "/jobs" not in schema["paths"]
        assert "/jobs/{job_id}" not in schema["paths"]
        assert "/jobs/{job_id}/result" not in schema["paths"]

    def test_job_service_registers_jobs_routes(self) -> None:
        client = TestClient(_APP)
        schema = client.get("/openapi.json").json()
        assert "/jobs" in schema["paths"]


# ===========================================================================
# No infrastructure leaks
# ===========================================================================


class TestNoInfrastructureLeaks:
    def setup_method(self) -> None:
        _reset_service()
        self.client = TestClient(_APP)

    def test_response_has_no_stack_trace(self) -> None:
        response = self.client.get("/jobs/no-such-job/result")
        assert response.status_code == 404
        assert "traceback" not in response.text.lower()
        assert "File" not in response.text
        assert "line" not in response.text
