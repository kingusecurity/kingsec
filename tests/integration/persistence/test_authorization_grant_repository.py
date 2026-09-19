"""Integration tests for SQLAlchemyAuthorizationGrantRepository (Phase 4).

Tests every public method against a real SQLite database. No mocks — the
repository is exercised through its port interface exactly as production
code would use it. Mirrors test_assessment_repository.py's own fixtures.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from kingsec.application.errors import AuthorizationGrantNotFoundError
from kingsec.domain import AuthorizationGrant, TargetSpecification, TargetSpecificationType
from kingsec.domain.identifiers import AuthorizationGrantId
from kingsec.infrastructure.persistence import create_database_engine, create_schema
from kingsec.infrastructure.persistence.repositories import SQLAlchemyAuthorizationGrantRepository

# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def engine():
    eng = create_database_engine(url="sqlite://")
    create_schema(eng)
    try:
        yield eng
    finally:
        eng.dispose()


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s
        s.rollback()


@pytest.fixture
def repo(session):
    return SQLAlchemyAuthorizationGrantRepository(session)


# ===========================================================================
# Helpers
# ===========================================================================


def make_grant(
    *,
    grant_id: AuthorizationGrantId | None = None,
    spec: TargetSpecification | None = None,
    valid_from: datetime = datetime(2026, 1, 1, tzinfo=UTC),
    valid_until: datetime = datetime(2026, 2, 1, tzinfo=UTC),
    revoked_at: datetime | None = None,
) -> AuthorizationGrant:
    return AuthorizationGrant(
        id=grant_id or AuthorizationGrantId.generate(),
        authorized_by="ciso@example.com",
        authorizing_organization="Example Corp",
        target_specification=spec or TargetSpecification(TargetSpecificationType.IP_ADDRESS, "203.0.113.5"),
        valid_from=valid_from,
        valid_until=valid_until,
        created_by="admin@kingusecurity.com",
        revoked_at=revoked_at,
    )


# ===========================================================================
# save() / get()
# ===========================================================================


class TestSaveAndGet:
    def test_round_trips_a_grant(self, repo: SQLAlchemyAuthorizationGrantRepository, session: Session) -> None:
        grant = make_grant()
        repo.save(grant)
        session.flush()

        loaded = repo.get(grant.id)
        assert loaded.id == grant.id
        assert loaded.authorized_by == grant.authorized_by
        assert loaded.authorizing_organization == grant.authorizing_organization
        assert loaded.target_specification == grant.target_specification
        assert loaded.valid_from == grant.valid_from
        assert loaded.valid_until == grant.valid_until
        assert loaded.created_by == grant.created_by
        assert loaded.revoked_at is None

    def test_round_trips_a_url_prefix_specification(
        self, repo: SQLAlchemyAuthorizationGrantRepository, session: Session
    ) -> None:
        grant = make_grant(spec=TargetSpecification(TargetSpecificationType.URL_PREFIX, "https://example.com/app/"))
        repo.save(grant)
        session.flush()

        loaded = repo.get(grant.id)
        assert loaded.target_specification.type == TargetSpecificationType.URL_PREFIX
        assert loaded.target_specification.value == "https://example.com/app/"

    def test_get_raises_not_found_for_unknown_id(self, repo: SQLAlchemyAuthorizationGrantRepository) -> None:
        with pytest.raises(AuthorizationGrantNotFoundError):
            repo.get(AuthorizationGrantId("agrt-does-not-exist"))

    def test_save_upserts_an_existing_grant(
        self, repo: SQLAlchemyAuthorizationGrantRepository, session: Session
    ) -> None:
        grant = make_grant()
        repo.save(grant)
        session.flush()

        revoked = AuthorizationGrant(
            id=grant.id,
            authorized_by=grant.authorized_by,
            authorizing_organization=grant.authorizing_organization,
            target_specification=grant.target_specification,
            valid_from=grant.valid_from,
            valid_until=grant.valid_until,
            created_by=grant.created_by,
            revoked_at=datetime(2026, 1, 15, tzinfo=UTC),
        )
        repo.save(revoked)
        session.flush()

        loaded = repo.get(grant.id)
        assert loaded.revoked_at == datetime(2026, 1, 15, tzinfo=UTC)


# ===========================================================================
# list()
# ===========================================================================


class TestList:
    def test_orders_by_valid_from_descending(
        self, repo: SQLAlchemyAuthorizationGrantRepository, session: Session
    ) -> None:
        older = make_grant(valid_from=datetime(2025, 1, 1, tzinfo=UTC), valid_until=datetime(2025, 2, 1, tzinfo=UTC))
        newer = make_grant(valid_from=datetime(2026, 1, 1, tzinfo=UTC), valid_until=datetime(2026, 2, 1, tzinfo=UTC))
        repo.save(older)
        repo.save(newer)
        session.flush()

        items = repo.list()
        assert [g.id for g in items] == [newer.id, older.id]

    def test_respects_limit_and_offset(
        self, repo: SQLAlchemyAuthorizationGrantRepository, session: Session
    ) -> None:
        for i in range(5):
            repo.save(
                make_grant(
                    valid_from=datetime(2026, 1, i + 1, tzinfo=UTC), valid_until=datetime(2026, 2, i + 1, tzinfo=UTC)
                )
            )
        session.flush()

        page = repo.list(limit=2, offset=1)
        assert len(page) == 2


# ===========================================================================
# find_active()
# ===========================================================================


class TestFindActive:
    def test_finds_grants_active_at_the_given_time(
        self, repo: SQLAlchemyAuthorizationGrantRepository, session: Session
    ) -> None:
        active = make_grant()
        expired = make_grant(
            valid_from=datetime(2020, 1, 1, tzinfo=UTC), valid_until=datetime(2020, 2, 1, tzinfo=UTC)
        )
        repo.save(active)
        repo.save(expired)
        session.flush()

        result = repo.find_active(datetime(2026, 1, 15, tzinfo=UTC))
        assert [g.id for g in result] == [active.id]

    def test_excludes_a_revoked_grant(self, repo: SQLAlchemyAuthorizationGrantRepository, session: Session) -> None:
        grant = make_grant(revoked_at=datetime(2026, 1, 10, tzinfo=UTC))
        repo.save(grant)
        session.flush()

        result = repo.find_active(datetime(2026, 1, 15, tzinfo=UTC))
        assert result == []


# ===========================================================================
# revoke()
# ===========================================================================


class TestRevoke:
    def test_revokes_an_existing_grant(
        self, repo: SQLAlchemyAuthorizationGrantRepository, session: Session
    ) -> None:
        grant = make_grant()
        repo.save(grant)
        session.flush()

        repo.revoke(grant.id, datetime(2026, 1, 10, tzinfo=UTC))
        session.flush()

        loaded = repo.get(grant.id)
        assert loaded.revoked_at == datetime(2026, 1, 10, tzinfo=UTC)

    def test_revoke_raises_not_found_for_unknown_id(self, repo: SQLAlchemyAuthorizationGrantRepository) -> None:
        with pytest.raises(AuthorizationGrantNotFoundError):
            repo.revoke(AuthorizationGrantId("agrt-does-not-exist"), datetime(2026, 1, 10, tzinfo=UTC))
