"""Integration test: enterprise audit event endpoints.

Verifies that:
1. GET /api/v1/audit/events requires authentication
2. GET /api/v1/audit/events requires ADMIN role
3. GET /api/v1/audit/events returns events with filters
4. GET /api/v1/audit/events/{id} returns a single event
5. GET /api/v1/audit/events/{id} returns 404 for missing event
"""

from __future__ import annotations

import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient

from kingsec.application.ports.outbound.audit_event_repository import AuditEventRepository
from kingsec.application.ports.outbound.rate_limiter import RateLimiterPort
from kingsec.application.use_cases.check_rate_limit import CheckRateLimit
from kingsec.application.use_cases.record_audit_event import RecordAuditEvent
from kingsec.application.use_cases.search_audit_events import SearchAuditEvents
from kingsec.domain.audit_event import (
    AuditAction,
    AuditEvent,
    AuditEventId,
    AuditOutcome,
    AuditSeverity,
)
from kingsec.domain.rate_limit import RateLimitDecision, RateLimitPolicy
from kingsec.infrastructure.config import Settings

from .test_auth_integration import StubHasher, StubTokenService, StubUserRepo


class StubAuditEventRepository(AuditEventRepository):
    def __init__(self) -> None:
        self._events: dict[str, AuditEvent] = {}

    def save(self, event: AuditEvent) -> None:
        self._events[str(event.id)] = event

    def find_by_id(self, event_id: AuditEventId) -> AuditEvent | None:
        return self._events.get(event_id.value)

    def search(
        self,
        *,
        actor_id: str | None = None,
        action: str | None = None,
        severity: str | None = None,
        outcome: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 50,
        offset: int = 0,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
    ) -> tuple[list[AuditEvent], int]:
        items = list(self._events.values())
        if actor_id:
            items = [e for e in items if e.actor_id == actor_id]
        if action:
            items = [e for e in items if e.action.value == action]
        if severity:
            items = [e for e in items if e.severity.value == severity]
        if outcome:
            items = [e for e in items if e.outcome.value == outcome]
        if resource_type:
            items = [e for e in items if e.resource_type == resource_type]
        if resource_id:
            items = [e for e in items if e.resource_id == resource_id]
        total = len(items)
        items = items[offset : offset + limit]
        return items, total


class StubRateLimiter(RateLimiterPort):
    def check(self, key: str, policy: RateLimitPolicy) -> RateLimitDecision:
        return RateLimitDecision(allowed=True, limit=policy.max_requests, remaining=policy.max_requests - 1, reset_seconds=policy.window_seconds)
    def record(self, key: str, policy: RateLimitPolicy) -> None:
        pass
    def reset(self, key: str) -> None:
        pass


def _build_app() -> tuple[FastAPI, StubAuditEventRepository, StubTokenService, StubUserRepo]:
    token_service = StubTokenService()
    user_repo = StubUserRepo()
    hasher = StubHasher()
    event_repo = StubAuditEventRepository()

    app = FastAPI()

    class _StubApp:
        settings = Settings()

        def resolve(self, service_type: type):
            from kingsec.application import Login, RefreshToken, RegisterUser
            from kingsec.application.ports import PasswordHasher, TokenService, UserRepository

            if service_type == TokenService:
                return token_service
            if service_type == UserRepository:
                return user_repo
            if service_type == PasswordHasher:
                return hasher
            if service_type == RegisterUser:
                return RegisterUser(user_repo, hasher)
            if service_type == Login:
                return Login(user_repo, hasher, token_service)
            if service_type == RefreshToken:
                return RefreshToken(user_repo, token_service)
            if service_type == AuditEventRepository:
                return event_repo
            if service_type == RecordAuditEvent:
                return RecordAuditEvent(event_repo)
            if service_type == SearchAuditEvents:
                return SearchAuditEvents(event_repo)
            if service_type == CheckRateLimit:
                return CheckRateLimit(StubRateLimiter())
            raise ValueError(f"Unknown service: {service_type}")

    app.state.kingsec_app = _StubApp()  # type: ignore[attr-defined]

    from kingsec.adapters.inbound.web.audit_events import router as audit_events_router
    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router

    register_error_handlers(app)
    app.include_router(router)
    app.include_router(audit_events_router)

    return app, event_repo, token_service, user_repo


def _register_and_login(
    client: TestClient,
    token_service: StubTokenService,
    user_repo: StubUserRepo,
    username: str = "adminuser",
    role: str = "ADMIN",
) -> str:
    """Helper: register a user and return an access token."""
    register_resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "Passw0rd!",
        },
    )
    assert register_resp.status_code in (200, 201)
    # Set the requested role directly in the repo.
    from kingsec.domain import Role
    user = user_repo.find_by_username(username)
    assert user is not None
    user.change_role(Role[role.upper()])
    user_repo.save(user)

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": "Passw0rd!"},
    )
    assert login_resp.status_code == 200
    return login_resp.json()["access_token"]


def _seed_events(repo: StubAuditEventRepository) -> None:
    events = [
        AuditEvent(
            id=AuditEventId(str(uuid.uuid4())),
            timestamp="2025-01-01T10:00:00+00:00",
            actor_id="user-1",
            actor_type="user",
            username="admin",
            ip_address="127.0.0.1",
            user_agent="",
            request_id="req-001",
            action=AuditAction.LOGIN_SUCCESS,
            resource_type="session",
            resource_id="sess-001",
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.INFO,
            message="Login successful",
        ),
        AuditEvent(
            id=AuditEventId(str(uuid.uuid4())),
            timestamp="2025-01-01T10:05:00+00:00",
            actor_id="user-2",
            actor_type="user",
            username="attacker",
            ip_address="10.0.0.1",
            user_agent="",
            request_id="req-002",
            action=AuditAction.LOGIN_FAILURE,
            resource_type="user",
            resource_id="",
            outcome=AuditOutcome.FAILURE,
            severity=AuditSeverity.WARNING,
            message="Invalid credentials",
        ),
        AuditEvent(
            id=AuditEventId(str(uuid.uuid4())),
            timestamp="2025-01-01T10:10:00+00:00",
            actor_id="user-1",
            actor_type="user",
            username="admin",
            ip_address="",
            user_agent="",
            request_id="req-003",
            action=AuditAction.ASSESSMENT_STARTED,
            resource_type="assessment",
            resource_id="assess-001",
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.INFO,
            message="Assessment started",
        ),
        AuditEvent(
            id=AuditEventId(str(uuid.uuid4())),
            timestamp="2025-01-01T11:00:00+00:00",
            actor_id="user-2",
            actor_type="user",
            username="attacker",
            ip_address="10.0.0.1",
            user_agent="",
            request_id="req-004",
            action=AuditAction.PERMISSION_DENIED,
            resource_type="assessment",
            resource_id="assess-002",
            outcome=AuditOutcome.DENIED,
            severity=AuditSeverity.CRITICAL,
            message="Permission denied",
        ),
    ]
    for event in events:
        repo.save(event)


class TestAuditEventsIntegration:
    def test_unauthenticated_access_returns_401(self) -> None:
        app, _, _, _ = _build_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit/events")
        assert resp.status_code == 401

    def test_non_admin_returns_403(self) -> None:
        app, _, token_service, user_repo = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        token = _register_and_login(client, token_service, user_repo, username="viewer", role="VIEWER")
        resp = client.get(
            "/api/v1/audit/events",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_get_events_empty(self) -> None:
        app, _, token_service, user_repo = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        token = _register_and_login(client, token_service, user_repo, username="admin1", role="ADMIN")
        resp = client.get(
            "/api/v1/audit/events",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_get_events_with_data(self) -> None:
        app, event_repo, token_service, user_repo = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        _seed_events(event_repo)
        token = _register_and_login(client, token_service, user_repo, username="admin2", role="ADMIN")
        resp = client.get(
            "/api/v1/audit/events",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 4
        assert data["total"] == 4

    def test_get_events_with_action_filter(self) -> None:
        app, event_repo, token_service, user_repo = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        _seed_events(event_repo)
        token = _register_and_login(client, token_service, user_repo, username="admin3", role="ADMIN")
        resp = client.get(
            "/api/v1/audit/events?action=login_success",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["action"] == "login_success"
        assert data["total"] == 1

    def test_get_events_with_severity_filter(self) -> None:
        app, event_repo, token_service, user_repo = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        _seed_events(event_repo)
        token = _register_and_login(client, token_service, user_repo, username="admin4", role="ADMIN")
        resp = client.get(
            "/api/v1/audit/events?severity=critical",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["severity"] == "critical"

    def test_get_events_with_outcome_filter(self) -> None:
        app, event_repo, token_service, user_repo = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        _seed_events(event_repo)
        token = _register_and_login(client, token_service, user_repo, username="admin5", role="ADMIN")
        resp = client.get(
            "/api/v1/audit/events?outcome=failure",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["outcome"] == "failure"

    def test_get_events_with_actor_filter(self) -> None:
        app, event_repo, token_service, user_repo = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        _seed_events(event_repo)
        token = _register_and_login(client, token_service, user_repo, username="admin6", role="ADMIN")
        resp = client.get(
            "/api/v1/audit/events?actor_id=user-1",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 2
        assert data["total"] == 2

    def test_get_events_with_pagination(self) -> None:
        app, event_repo, token_service, user_repo = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        _seed_events(event_repo)
        token = _register_and_login(client, token_service, user_repo, username="admin7", role="ADMIN")
        resp = client.get(
            "/api/v1/audit/events?limit=2&offset=1",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 2
        assert data["total"] == 4
        assert data["limit"] == 2
        assert data["offset"] == 1

    def test_get_event_by_id(self) -> None:
        app, event_repo, token_service, user_repo = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        _seed_events(event_repo)
        token = _register_and_login(client, token_service, user_repo, username="admin8", role="ADMIN")

        # First get the list to find an event ID
        list_resp = client.get(
            "/api/v1/audit/events",
            headers={"Authorization": f"Bearer {token}"},
        )
        event_id = list_resp.json()["items"][0]["event_id"]

        resp = client.get(
            f"/api/v1/audit/events/{event_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["event_id"] == event_id
        assert "action" in data
        assert "timestamp" in data
        assert "actor_id" in data

    def test_get_event_by_id_not_found(self) -> None:
        app, _, token_service, user_repo = _build_app()
        client = TestClient(app, raise_server_exceptions=False)

        token = _register_and_login(client, token_service, user_repo, username="admin9", role="ADMIN")
        resp = client.get(
            "/api/v1/audit/events/nonexistent-id",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 404

    def test_get_event_by_id_unauthenticated(self) -> None:
        app, _, _, _ = _build_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/audit/events/some-id")
        assert resp.status_code == 401
