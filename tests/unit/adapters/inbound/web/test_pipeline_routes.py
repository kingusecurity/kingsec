from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application.ports.pipeline_service import PipelineServicePort
from kingsec.domain import Role
from kingsec.domain.pipeline import (
    PIPELINE_ORDER,
    PipelineExecution,
    PipelineId,
    PipelineResult,
    PipelineStage,
    PipelineState,
)


@pytest.fixture
def mock_service() -> MagicMock:
    return MagicMock(spec=PipelineServicePort)


def _make_execution(state: PipelineState = PipelineState.QUEUED) -> PipelineExecution:
    stages = tuple(
        PipelineStage(name=s.value, status="completed" if s == state else "pending",
                      started_at="2025-01-01T00:00:00")
        for s in PIPELINE_ORDER[:1]
    )
    return PipelineExecution(
        pipeline_id=PipelineId(value="pl-1"),
        target="10.0.0.1",
        state=state,
        stages=stages,
        owner_user_id="u1",
        scanner_ids=("nuclei",),
        priority="normal",
    )


@pytest.fixture
def app(mock_service: MagicMock) -> TestClient:
    with patch("kingsec.bootstrap.application.Application") as MockApp:
        app_instance = MockApp()
        app_instance.resolve.return_value = mock_service

        app = FastAPI()
        from kingsec.adapters.inbound.web.pipeline_routes import router
        app.include_router(router)
        app.state.kingsec_app = app_instance

        from kingsec.adapters.inbound.web.auth import get_current_user
        app.dependency_overrides[get_current_user] = lambda: type(
            "User", (), {"user_id": "admin", "username": "admin",
                         "role": Role.ADMIN, "claims": None}
        )()
        return TestClient(app)


class TestPipelineRoutes:
    def test_start_pipeline(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.start_pipeline.return_value = _make_execution()
        resp = app.post("/api/v1/pipelines/start", json={
            "target": "10.0.0.1",
            "scanner_ids": ["nuclei"],
            "priority": "high",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["message"] == "Pipeline started"
        assert data["pipeline"]["pipeline_id"] == "pl-1"
        assert data["pipeline"]["state"] == "queued"

    def test_list_pipelines(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.list_pipelines.return_value = [_make_execution(), _make_execution(PipelineState.RUNNING)]
        resp = app.get("/api/v1/pipelines")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["pipelines"]) == 2

    def test_get_pipeline(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.get_pipeline.return_value = _make_execution()
        resp = app.get("/api/v1/pipelines/pl-1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["pipeline_id"] == "pl-1"

    def test_get_pipeline_not_found(self, app: TestClient, mock_service: MagicMock) -> None:
        from kingsec.application.errors import PipelineNotFoundError
        mock_service.get_pipeline.side_effect = PipelineNotFoundError("not found")
        resp = app.get("/api/v1/pipelines/pl-missing")
        assert resp.status_code == 404

    def test_cancel_pipeline(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.cancel_pipeline.return_value = _make_execution(PipelineState.CANCELLED)
        resp = app.post("/api/v1/pipelines/pl-1/cancel", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert "cancelled" in data["message"]

    def test_cancel_pipeline_not_found(self, app: TestClient, mock_service: MagicMock) -> None:
        from kingsec.application.errors import PipelineNotFoundError
        mock_service.cancel_pipeline.side_effect = PipelineNotFoundError("not found")
        resp = app.post("/api/v1/pipelines/pl-missing/cancel", json={})
        assert resp.status_code == 404

    def test_retry_pipeline(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.retry_pipeline.return_value = _make_execution(PipelineState.FAILED)
        resp = app.post("/api/v1/pipelines/pl-1/retry", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert "retried" in data["message"]

    def test_retry_pipeline_conflict(self, app: TestClient, mock_service: MagicMock) -> None:
        from kingsec.application.errors import PipelineStateConflictError
        mock_service.retry_pipeline.side_effect = PipelineStateConflictError("conflict")
        resp = app.post("/api/v1/pipelines/pl-1/retry", json={})
        assert resp.status_code == 409

    def test_pause_pipeline(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.pause_pipeline.return_value = _make_execution()
        resp = app.post("/api/v1/pipelines/pl-1/pause", json={})
        assert resp.status_code == 200
        assert "paused" in resp.json()["message"]

    def test_resume_pipeline(self, app: TestClient, mock_service: MagicMock) -> None:
        mock_service.resume_pipeline.return_value = _make_execution()
        resp = app.post("/api/v1/pipelines/pl-1/resume", json={})
        assert resp.status_code == 200
        assert "resumed" in resp.json()["message"]

    def test_unauthorized_without_admin(self, app: TestClient, mock_service: MagicMock) -> None:
        from kingsec.adapters.inbound.web.auth import get_current_user
        app.app.dependency_overrides[get_current_user] = lambda: type(
            "User", (), {"user_id": "viewer", "username": "viewer",
                         "role": Role.VIEWER, "claims": None}
        )()
        resp = app.post("/api/v1/pipelines/start", json={"target": "10.0.0.1"})
        assert resp.status_code == 403

    def test_get_pipeline_has_stages(self, app: TestClient, mock_service: MagicMock) -> None:
        exec_ = _make_execution()
        mock_service.get_pipeline.return_value = exec_
        resp = app.get("/api/v1/pipelines/pl-1")
        data = resp.json()
        assert "stages" in data
        assert data["stages"][0]["name"] == "queued"
