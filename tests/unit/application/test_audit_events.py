"""Tests for enterprise audit event use cases."""

from __future__ import annotations

import pytest

from kingsec.application.ports.outbound.audit_event_repository import AuditEventRepository
from kingsec.application.use_cases.audit_dto import (
    RecordAuditEventRequest,
    SearchAuditEventsRequest,
)
from kingsec.application.use_cases.record_audit_event import RecordAuditEvent
from kingsec.application.use_cases.search_audit_events import SearchAuditEvents
from kingsec.domain.audit_event import (
    AuditAction,
    AuditEvent,
    AuditEventId,
    AuditOutcome,
    AuditSeverity,
)


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


class TestRecordAuditEvent:
    def test_record_success_event(self) -> None:
        repo = StubAuditEventRepository()
        use_case = RecordAuditEvent(repo)

        result = use_case.execute(
            RecordAuditEventRequest(
                actor_id="user-1",
                actor_type="user",
                username="admin",
                ip_address="127.0.0.1",
                user_agent="TestAgent/1.0",
                request_id="req-001",
                action="login_success",
                resource_type="session",
                resource_id="sess-001",
                outcome="success",
                severity="info",
                message="User logged in",
            )
        )

        assert result.event_id
        event = repo.find_by_id(AuditEventId(result.event_id))
        assert event is not None
        assert event.actor_id == "user-1"
        assert event.action == AuditAction.LOGIN_SUCCESS
        assert event.outcome == AuditOutcome.SUCCESS

    def test_record_failure_event(self) -> None:
        repo = StubAuditEventRepository()
        use_case = RecordAuditEvent(repo)

        result = use_case.execute(
            RecordAuditEventRequest(
                actor_id="unknown",
                actor_type="user",
                username="attacker",
                ip_address="10.0.0.1",
                user_agent="",
                request_id="req-002",
                action="login_failure",
                resource_type="user",
                resource_id="",
                outcome="failure",
                severity="warning",
                message="Invalid credentials",
            )
        )

        event = repo.find_by_id(AuditEventId(result.event_id))
        assert event is not None
        assert event.action == AuditAction.LOGIN_FAILURE
        assert event.outcome == AuditOutcome.FAILURE
        assert event.severity == AuditSeverity.WARNING

    def test_record_denied_event(self) -> None:
        repo = StubAuditEventRepository()
        use_case = RecordAuditEvent(repo)

        result = use_case.execute(
            RecordAuditEventRequest(
                actor_id="user-2",
                actor_type="user",
                username="viewer",
                ip_address="",
                user_agent="",
                request_id="req-003",
                action="permission_denied",
                resource_type="assessment",
                resource_id="assess-001",
                outcome="denied",
                severity="error",
                message="Insufficient permissions",
            )
        )

        event = repo.find_by_id(AuditEventId(result.event_id))
        assert event is not None
        assert event.action == AuditAction.PERMISSION_DENIED
        assert event.outcome == AuditOutcome.DENIED
        assert event.severity == AuditSeverity.ERROR

    def test_invalid_action_raises_error(self) -> None:
        repo = StubAuditEventRepository()
        use_case = RecordAuditEvent(repo)

        with pytest.raises(Exception):
            use_case.execute(
                RecordAuditEventRequest(
                    actor_id="user-1",
                    actor_type="user",
                    username="admin",
                    ip_address="",
                    user_agent="",
                    request_id="",
                    action="invalid_action",
                    resource_type="",
                    resource_id="",
                    outcome="success",
                    severity="info",
                    message="",
                )
            )

    def test_record_with_metadata(self) -> None:
        repo = StubAuditEventRepository()
        use_case = RecordAuditEvent(repo)

        result = use_case.execute(
            RecordAuditEventRequest(
                actor_id="user-1",
                actor_type="user",
                username="admin",
                ip_address="",
                user_agent="",
                request_id="req-004",
                action="api_key_created",
                resource_type="api_key",
                resource_id="key-001",
                outcome="success",
                severity="info",
                message="API key created",
                metadata={"key_name": "ci-cd-token", "scope": "read_only"},
            )
        )

        event = repo.find_by_id(AuditEventId(result.event_id))
        assert event is not None
        assert event.metadata == {"key_name": "ci-cd-token", "scope": "read_only"}


class TestSearchAuditEvents:
    def test_search_all(self) -> None:
        repo = StubAuditEventRepository()
        _seed_events(repo)

        use_case = SearchAuditEvents(repo)
        result = use_case.execute(SearchAuditEventsRequest(limit=50))

        assert result.total == 5
        assert len(result.items) == 5

    def test_search_with_limit(self) -> None:
        repo = StubAuditEventRepository()
        _seed_events(repo)

        use_case = SearchAuditEvents(repo)
        result = use_case.execute(SearchAuditEventsRequest(limit=2))

        assert result.total == 5
        assert len(result.items) == 2

    def test_search_with_offset(self) -> None:
        repo = StubAuditEventRepository()
        _seed_events(repo)

        use_case = SearchAuditEvents(repo)
        result = use_case.execute(SearchAuditEventsRequest(limit=50, offset=2))

        assert result.total == 5
        assert len(result.items) == 3

    def test_search_by_action(self) -> None:
        repo = StubAuditEventRepository()
        _seed_events(repo)

        use_case = SearchAuditEvents(repo)
        result = use_case.execute(SearchAuditEventsRequest(action="login_success"))

        assert result.total == 1
        assert all(v.action == "login_success" for v in result.items)

    def test_search_by_severity(self) -> None:
        repo = StubAuditEventRepository()
        _seed_events(repo)

        use_case = SearchAuditEvents(repo)
        result = use_case.execute(SearchAuditEventsRequest(severity="critical"))

        assert result.total == 1

    def test_search_by_outcome(self) -> None:
        repo = StubAuditEventRepository()
        _seed_events(repo)

        use_case = SearchAuditEvents(repo)
        result = use_case.execute(SearchAuditEventsRequest(outcome="failure"))

        assert result.total == 1

    def test_search_by_actor_id(self) -> None:
        repo = StubAuditEventRepository()
        _seed_events(repo)

        use_case = SearchAuditEvents(repo)
        result = use_case.execute(SearchAuditEventsRequest(actor_id="user-1"))

        assert result.total == 2

    def test_search_by_resource_type(self) -> None:
        repo = StubAuditEventRepository()
        _seed_events(repo)

        use_case = SearchAuditEvents(repo)
        result = use_case.execute(SearchAuditEventsRequest(resource_type="api_key"))

        assert result.total == 1

    def test_search_by_resource_id(self) -> None:
        repo = StubAuditEventRepository()
        _seed_events(repo)

        use_case = SearchAuditEvents(repo)
        result = use_case.execute(SearchAuditEventsRequest(resource_id="assess-001"))

        assert result.total == 1

    def test_search_no_results(self) -> None:
        repo = StubAuditEventRepository()
        _seed_events(repo)

        use_case = SearchAuditEvents(repo)
        result = use_case.execute(SearchAuditEventsRequest(action="logout"))

        assert result.total == 0
        assert len(result.items) == 0

    def test_limit_clamped_to_max_200(self) -> None:
        repo = StubAuditEventRepository()
        _seed_events(repo)

        use_case = SearchAuditEvents(repo)
        result = use_case.execute(SearchAuditEventsRequest(limit=999))

        assert result.total == 5
        assert len(result.items) == 5

    def test_limit_clamped_to_min_1(self) -> None:
        repo = StubAuditEventRepository()
        _seed_events(repo)

        use_case = SearchAuditEvents(repo)
        result = use_case.execute(SearchAuditEventsRequest(limit=0))

        assert result.total == 5
        assert len(result.items) == 1

    def test_negative_offset_clamped(self) -> None:
        repo = StubAuditEventRepository()
        _seed_events(repo)

        use_case = SearchAuditEvents(repo)
        result = use_case.execute(SearchAuditEventsRequest(limit=50, offset=-1))

        assert result.total == 5
        assert len(result.items) == 5

    def test_search_empty_store(self) -> None:
        repo = StubAuditEventRepository()
        use_case = SearchAuditEvents(repo)

        result = use_case.execute(SearchAuditEventsRequest(limit=50))
        assert result.total == 0
        assert len(result.items) == 0


def _seed_events(repo: StubAuditEventRepository) -> None:
    import uuid

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
            timestamp="2025-01-01T10:15:00+00:00",
            actor_id="user-3",
            actor_type="api_key",
            username="ci-bot",
            ip_address="",
            user_agent="",
            request_id="req-004",
            action=AuditAction.API_KEY_CREATED,
            resource_type="api_key",
            resource_id="key-001",
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.INFO,
            message="API key created",
        ),
        AuditEvent(
            id=AuditEventId(str(uuid.uuid4())),
            timestamp="2025-01-01T11:00:00+00:00",
            actor_id="user-2",
            actor_type="user",
            username="attacker",
            ip_address="10.0.0.1",
            user_agent="",
            request_id="req-005",
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
