"""Tests for the SQLAlchemy audit repository."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.infrastructure.persistence.audit_repository import SqlAlchemyAuditRepository
from kingsec.infrastructure.persistence.models import Base


@pytest.fixture
def engine():
    """Create an in-memory SQLite engine with foreign keys enabled."""
    eng = create_engine("sqlite:///:memory:", future=True)

    @event.listens_for(eng, "connect")
    def _enable_fk(dbapi_conn, _):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def repo(session_factory):
    return SqlAlchemyAuditRepository(session_factory)


class TestSqlAlchemyAuditRepository:
    def test_record_and_list(self, repo: SqlAlchemyAuditRepository) -> None:
        entry = AuditEntry(
            action=AuditAction.LOGIN,
            resource_type="user",
            resource_id="user-1",
            success=True,
            user_id="user-1",
            username="admin",
            role="ADMIN",
            ip_address="127.0.0.1",
        )
        repo.record(entry)

        entries = repo.list_entries()
        assert len(entries) == 1
        assert entries[0].action == AuditAction.LOGIN
        assert entries[0].resource_type == "user"
        assert entries[0].success is True
        assert entries[0].ip_address == "127.0.0.1"

    def test_append_only_no_delete(self, repo: SqlAlchemyAuditRepository) -> None:
        for i in range(5):
            repo.record(
                AuditEntry(
                    action=AuditAction.LOGIN,
                    resource_id=f"user-{i}",
                )
            )
        entries = repo.list_entries()
        assert len(entries) == 5

    def test_list_ordered_by_timestamp_desc(self, repo: SqlAlchemyAuditRepository) -> None:
        repo.record(AuditEntry(action=AuditAction.LOGIN, timestamp="2025-01-01T00:00:00+00:00"))
        repo.record(AuditEntry(action=AuditAction.LOGOUT, timestamp="2025-01-02T00:00:00+00:00"))
        repo.record(AuditEntry(action=AuditAction.LOGIN, timestamp="2025-01-03T00:00:00+00:00"))

        entries = repo.list_entries()
        assert [e.action for e in entries] == [
            AuditAction.LOGIN,
            AuditAction.LOGOUT,
            AuditAction.LOGIN,
        ]
        # Most recent first
        assert entries[0].timestamp == "2025-01-03T00:00:00+00:00"

    def test_filter_by_user_id(self, repo: SqlAlchemyAuditRepository) -> None:
        repo.record(AuditEntry(action=AuditAction.LOGIN, user_id="user-1"))
        repo.record(AuditEntry(action=AuditAction.LOGIN, user_id="user-2"))
        repo.record(AuditEntry(action=AuditAction.LOGOUT, user_id="user-1"))

        entries = repo.list_entries(user_id="user-1")
        assert len(entries) == 2
        assert all(e.user_id == "user-1" for e in entries)

    def test_filter_by_action(self, repo: SqlAlchemyAuditRepository) -> None:
        repo.record(AuditEntry(action=AuditAction.LOGIN))
        repo.record(AuditEntry(action=AuditAction.LOGOUT))
        repo.record(AuditEntry(action=AuditAction.LOGIN))

        entries = repo.list_entries(action="login")
        assert len(entries) == 2

    def test_filter_by_resource_type(self, repo: SqlAlchemyAuditRepository) -> None:
        repo.record(AuditEntry(action=AuditAction.LOGIN, resource_type="user"))
        repo.record(AuditEntry(action=AuditAction.ASSESSMENT_CREATED, resource_type="assessment"))

        entries = repo.list_entries(resource_type="assessment")
        assert len(entries) == 1

    def test_filter_by_success(self, repo: SqlAlchemyAuditRepository) -> None:
        repo.record(AuditEntry(action=AuditAction.LOGIN, success=True))
        repo.record(AuditEntry(action=AuditAction.FAILED_LOGIN, success=False))
        repo.record(AuditEntry(action=AuditAction.LOGIN, success=True))

        success_entries = repo.list_entries(success_only=True)
        assert len(success_entries) == 2

        failure_entries = repo.list_entries(success_only=False)
        assert len(failure_entries) == 1

    def test_filter_by_timestamp_range(self, repo: SqlAlchemyAuditRepository) -> None:
        repo.record(AuditEntry(action=AuditAction.LOGIN, timestamp="2025-01-01T00:00:00+00:00"))
        repo.record(AuditEntry(action=AuditAction.LOGIN, timestamp="2025-06-15T00:00:00+00:00"))
        repo.record(AuditEntry(action=AuditAction.LOGIN, timestamp="2025-12-31T00:00:00+00:00"))

        entries = repo.list_entries(since="2025-06-01T00:00:00+00:00")
        assert len(entries) == 2

        entries = repo.list_entries(until="2025-06-30T00:00:00+00:00")
        assert len(entries) == 2

    def test_pagination(self, repo: SqlAlchemyAuditRepository) -> None:
        for i in range(10):
            repo.record(AuditEntry(action=AuditAction.LOGIN, resource_id=str(i)))

        page1 = repo.list_entries(limit=3, offset=0)
        assert len(page1) == 3

        page2 = repo.list_entries(limit=3, offset=3)
        assert len(page2) == 3

        page4 = repo.list_entries(limit=3, offset=9)
        assert len(page4) == 1

    def test_count_entries(self, repo: SqlAlchemyAuditRepository) -> None:
        repo.record(AuditEntry(action=AuditAction.LOGIN, user_id="user-1"))
        repo.record(AuditEntry(action=AuditAction.LOGIN, user_id="user-2"))
        repo.record(AuditEntry(action=AuditAction.LOGOUT, user_id="user-1"))

        assert repo.count_entries() == 3
        assert repo.count_entries(user_id="user-1") == 2
        assert repo.count_entries(action="login") == 2

    def test_metadata_roundtrip(self, repo: SqlAlchemyAuditRepository) -> None:
        entry = AuditEntry(
            action=AuditAction.ASSESSMENT_CREATED,
            metadata={"target": "10.0.0.1", "count": 42},
        )
        repo.record(entry)

        entries = repo.list_entries()
        assert entries[0].metadata == {"target": "10.0.0.1", "count": 42}

    def test_empty_list(self, repo: SqlAlchemyAuditRepository) -> None:
        entries = repo.list_entries()
        assert entries == []

    def test_clamped_limit(self, repo: SqlAlchemyAuditRepository) -> None:
        for _i in range(5):
            repo.record(AuditEntry(action=AuditAction.LOGIN))
        # Limit > 200 should be clamped
        entries = repo.list_entries(limit=500)
        assert len(entries) == 5
