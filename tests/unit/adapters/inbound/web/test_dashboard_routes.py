from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from kingsec.application.ports import TokenClaims
from kingsec.domain import Role
from kingsec.domain.dashboard import (
    DashboardSummary,
    JobStatistics,
    NotificationStatistics,
    ScheduleStatistics,
    SeverityBreakdown,
    TrendPoint,
)


@pytest.fixture
def mock_service() -> MagicMock:
    service = MagicMock()
    service.get_summary.return_value = DashboardSummary(
        total_scans=100, successful_scans=80, failed_scans=20,
        total_findings=500, critical_findings=10, high_findings=50,
        medium_findings=100, low_findings=340,
    )
    service.get_severity_breakdown.return_value = SeverityBreakdown(
        critical=10, high=50, medium=100, low=300, info=40,
    )
    service.get_trend_data.return_value = [
        TrendPoint(date="2025-01-01", value=10.0),
        TrendPoint(date="2025-01-08", value=15.0),
    ]
    service.get_scanner_statistics.return_value = []
    service.get_worker_statistics.return_value = []
    service.get_job_statistics.return_value = JobStatistics(
        pending=2, running=1, completed=80, failed=10, cancelled=7,
    )
    service.get_schedule_statistics.return_value = ScheduleStatistics(
        total=20, active=15, paused=3, disabled=2,
    )
    service.get_notification_statistics.return_value = NotificationStatistics(
        total=200, sent=180, failed=10, pending=5, read_count=5,
    )
    service.get_recent_activity.return_value = [
        {"id": "a1", "type": "assessment", "action": "COMPLETED", "target": "example.com", "timestamp": "now"},
    ]
    return service


@pytest.fixture
def app(mock_service: MagicMock) -> TestClient:
    with patch("kingsec.bootstrap.application.Application") as MockApp:
        app_instance = MockApp()
        app_instance.resolve.return_value = mock_service

        from fastapi import FastAPI
        app = FastAPI()
        from kingsec.adapters.inbound.web.versioning import register_versioned_routes
        register_versioned_routes(app)
        app.state.kingsec_app = app_instance
        client = TestClient(app)
        from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user
        app.dependency_overrides[get_current_user] = lambda: CurrentUser(
            user_id="user1",
            username="test",
            role=Role.ADMIN,
            claims=TokenClaims(
                user_id="user1", username="test", role="admin",
                token_type="access", jti="test-jti",
                issued_at=datetime.now(), expires_at=datetime.now(),
            ),
        )
        return client


class TestDashboardRoot:
    def test_root_returns_200(self, app: TestClient) -> None:
        response = app.get("/api/v1/dashboard")
        assert response.status_code == 200

    def test_root_contains_summary(self, app: TestClient) -> None:
        response = app.get("/api/v1/dashboard")
        data = response.json()
        assert "summary" in data
        assert data["summary"]["total_scans"] == 100


class TestDashboardSummary:
    def test_summary_returns_200(self, app: TestClient) -> None:
        response = app.get("/api/v1/dashboard/summary")
        assert response.status_code == 200

    def test_summary_contents(self, app: TestClient) -> None:
        response = app.get("/api/v1/dashboard/summary")
        data = response.json()
        assert data["total_scans"] == 100
        assert data["successful_scans"] == 80


class TestDashboardSeverity:
    def test_severity_returns_200(self, app: TestClient) -> None:
        response = app.get("/api/v1/dashboard/severity")
        assert response.status_code == 200

    def test_severity_contents(self, app: TestClient) -> None:
        response = app.get("/api/v1/dashboard/severity")
        data = response.json()
        assert data["critical"] == 10


class TestDashboardTrends:
    def test_trends_returns_200(self, app: TestClient) -> None:
        response = app.get("/api/v1/dashboard/trends")
        assert response.status_code == 200

    def test_trends_period(self, app: TestClient) -> None:
        response = app.get("/api/v1/dashboard/trends?period=daily&limit=5")
        assert response.status_code == 200


class TestDashboardJobs:
    def test_jobs_returns_200(self, app: TestClient) -> None:
        response = app.get("/api/v1/dashboard/jobs")
        assert response.status_code == 200


class TestDashboardSchedules:
    def test_schedules_returns_200(self, app: TestClient) -> None:
        response = app.get("/api/v1/dashboard/schedules")
        assert response.status_code == 200


class TestDashboardNotifications:
    def test_notifications_returns_200(self, app: TestClient) -> None:
        response = app.get("/api/v1/dashboard/notifications")
        assert response.status_code == 200


class TestDashboardActivity:
    def test_activity_returns_200(self, app: TestClient) -> None:
        response = app.get("/api/v1/dashboard/activity")
        assert response.status_code == 200

    def test_activity_contents(self, app: TestClient) -> None:
        response = app.get("/api/v1/dashboard/activity")
        data = response.json()
        assert "activity" in data
        assert len(data["activity"]) == 1


class TestDashboardScanners:
    def test_scanners_returns_200(self, app: TestClient) -> None:
        response = app.get("/api/v1/dashboard/scanners")
        assert response.status_code == 200


class TestDashboardWorkers:
    def test_workers_returns_200(self, app: TestClient) -> None:
        response = app.get("/api/v1/dashboard/workers")
        assert response.status_code == 200
