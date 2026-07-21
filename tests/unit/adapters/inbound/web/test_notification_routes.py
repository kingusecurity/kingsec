from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from kingsec.application.ports import TokenClaims
from kingsec.domain import Role
from kingsec.domain.notification import (
    Notification,
    NotificationChannel,
    NotificationId,
    NotificationPriority,
    NotificationStatus,
)


@pytest.fixture
def mock_service() -> MagicMock:
    service = MagicMock()
    n = Notification(
        id=NotificationId("n1"),
        user_id="user1",
        title="Test",
        message="Hello",
        channel=NotificationChannel.IN_APP,
        status=NotificationStatus.SENT,
        priority=NotificationPriority.MEDIUM,
        event_type="test_event",
        template_vars={},
        retry_count=0,
        max_retries=3,
        created_at="now",
        updated_at="now",
    )
    service.get.return_value = n
    service.list_by_user.return_value = ([n], 1)
    service.list_all.return_value = ([n], 1)
    service.send.return_value = n
    service.send_bulk.return_value = [n]
    service.mark_read.return_value = n
    service.retry_failed.return_value = n
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
                user_id="user1",
                username="test",
                role="admin",
                token_type="access",
                jti="test-jti",
                issued_at=datetime.now(),
                expires_at=datetime.now(),
            ),
        )
        return client


class TestListNotifications:
    def test_list_returns_200(self, app: TestClient) -> None:
        response = app.get("/api/v1/notifications")
        assert response.status_code == 200

    def test_list_contains_notifications(self, app: TestClient, mock_service: MagicMock) -> None:
        response = app.get("/api/v1/notifications")
        data = response.json()
        assert "notifications" in data
        assert "total" in data


class TestGetNotification:
    def test_get_returns_200(self, app: TestClient) -> None:
        response = app.get("/api/v1/notifications/n1")
        assert response.status_code == 200

    def test_get_nonexistent_returns_404(self, app: TestClient, mock_service: MagicMock) -> None:
        from kingsec.application.errors import NotificationNotFoundError
        mock_service.get.side_effect = NotificationNotFoundError("not found")
        response = app.get("/api/v1/notifications/nonexistent")
        assert response.status_code == 404


class TestSendNotification:
    def test_send_returns_200(self, app: TestClient) -> None:
        response = app.post("/api/v1/notifications/send", json={
            "channel": "in_app",
            "event_type": "test",
            "priority": "medium",
        })
        assert response.status_code == 200


class TestBulk:
    def test_bulk_returns_200(self, app: TestClient) -> None:
        response = app.post("/api/v1/notifications/bulk", json={
            "notifications": [
                {"channel": "in_app", "event_type": "test"},
            ]
        })
        assert response.status_code == 200


class TestMarkRead:
    def test_mark_read_returns_200(self, app: TestClient) -> None:
        response = app.post("/api/v1/notifications/n1/read")
        assert response.status_code == 200


class TestDelete:
    def test_delete_returns_204(self, app: TestClient) -> None:
        response = app.delete("/api/v1/notifications/n1")
        assert response.status_code == 204


class TestRetry:
    def test_retry_returns_200(self, app: TestClient) -> None:
        response = app.post("/api/v1/notifications/retry", json={"notification_id": "n1"})
        assert response.status_code == 200

    def test_retry_missing_id_returns_422(self, app: TestClient) -> None:
        response = app.post("/api/v1/notifications/retry", json={})
        assert response.status_code == 422
