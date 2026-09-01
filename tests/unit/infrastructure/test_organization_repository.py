"""Tests for the SQLAlchemy organization repository - KSEC-84-01.

Phase 84: organization_memberships/team_memberships had no DB-level
uniqueness guard on (user_id, organization_id)/(user_id, team_id), and
add_member()/add_team_member() each did a separate SELECT-then-INSERT
with no backstop - two concurrent calls for the same pair could both
insert. Beyond the duplicate row itself, get_member_role() (the
pervasive authorization gate for every organization/team route) uses
scalar_one_or_none(), which raises MultipleResultsFound once a duplicate
exists - turning every subsequent authorization check for that user in
that org into an unhandled 500. These tests exercise the REAL
SQLAlchemyOrganizationRepository against a real on-disk SQLite database,
including a genuine multi-threaded concurrency test, matching the
established pattern in test_user_repository.py for the identical class
of concurrent-insert race (KSEC-73-05).
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kingsec.domain.organization import (
    Organization,
    OrganizationId,
    OrganizationMembership,
    OrgRole,
    Team,
    TeamId,
    TeamMembership,
)
from kingsec.infrastructure.persistence.models import Base
from kingsec.infrastructure.persistence.repositories.organization import SQLAlchemyOrganizationRepository


@pytest.fixture
def engine(tmp_path: Path):
    """A real on-disk SQLite database file - see test_user_repository.py's
    identical fixture for why a single shared StaticPool connection was
    rejected (each thread needs its own independent DBAPI connection,
    subject to SQLite's own file-level locking, for a genuine concurrency
    test to be meaningful)."""
    db_path = tmp_path / f"orgs-{uuid.uuid4().hex}.sqlite3"
    eng = create_engine(f"sqlite:///{db_path}", future=True, connect_args={"timeout": 30})
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@pytest.fixture
def repo(session_factory) -> SQLAlchemyOrganizationRepository:
    return SQLAlchemyOrganizationRepository(session_factory)


def _make_org(repo: SQLAlchemyOrganizationRepository) -> Organization:
    org = Organization(id=OrganizationId.generate(), name="Acme", slug=f"acme-{uuid.uuid4().hex[:8]}")
    repo.save(org)
    return org


class TestAddMemberIdempotency:
    def test_calling_add_member_twice_for_the_same_pair_results_in_one_row(
        self, repo: SQLAlchemyOrganizationRepository
    ) -> None:
        org = _make_org(repo)
        membership = OrganizationMembership(user_id="alice", organization_id=str(org.id), role=OrgRole.VIEWER)

        repo.add_member(membership)
        repo.add_member(membership)  # simulates the race: a second insert attempt for the same pair

        members = repo.list_members(str(org.id))
        assert len(members) == 1

    def test_get_member_role_does_not_crash_after_a_duplicate_add_attempt(
        self, repo: SQLAlchemyOrganizationRepository
    ) -> None:
        """The concrete failure mode this fixes: get_member_role() used
        scalar_one_or_none(), which raises MultipleResultsFound once a
        duplicate row exists - breaking every subsequent authorization
        check for this user/org pair."""
        org = _make_org(repo)
        membership = OrganizationMembership(user_id="alice", organization_id=str(org.id), role=OrgRole.ADMIN)

        repo.add_member(membership)
        repo.add_member(membership)

        assert repo.get_member_role(str(org.id), "alice") == OrgRole.ADMIN

    def test_concurrent_add_member_for_the_same_pair_does_not_duplicate(
        self, session_factory
    ) -> None:
        """Genuine concurrency, not just a sequential double-call: two
        threads race to add the same user to the same organization."""
        repo = SQLAlchemyOrganizationRepository(session_factory)
        org = _make_org(repo)
        membership = OrganizationMembership(user_id="bob", organization_id=str(org.id), role=OrgRole.VIEWER)

        errors: list[BaseException] = []
        start = threading.Barrier(2)

        def _add() -> None:
            try:
                start.wait(timeout=5)
                repo.add_member(membership)
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_add) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert errors == [], f"add_member raised under concurrency: {errors!r}"
        assert len(repo.list_members(str(org.id))) == 1
        assert repo.get_member_role(str(org.id), "bob") == OrgRole.VIEWER


class TestAddTeamMemberIdempotency:
    def test_calling_add_team_member_twice_for_the_same_pair_results_in_one_row(
        self, repo: SQLAlchemyOrganizationRepository
    ) -> None:
        org = _make_org(repo)
        team = Team(id=TeamId.generate(), organization_id=str(org.id), name="Red Team")
        repo.save_team(team)
        membership = TeamMembership(user_id="alice", team_id=str(team.id))

        repo.add_team_member(membership)
        repo.add_team_member(membership)

        assert len(repo.list_team_members(str(team.id))) == 1

    def test_concurrent_add_team_member_for_the_same_pair_does_not_duplicate(
        self, session_factory
    ) -> None:
        repo = SQLAlchemyOrganizationRepository(session_factory)
        org = _make_org(repo)
        team = Team(id=TeamId.generate(), organization_id=str(org.id), name="Red Team")
        repo.save_team(team)
        membership = TeamMembership(user_id="bob", team_id=str(team.id))

        errors: list[BaseException] = []
        start = threading.Barrier(2)

        def _add() -> None:
            try:
                start.wait(timeout=5)
                repo.add_team_member(membership)
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_add) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert errors == [], f"add_team_member raised under concurrency: {errors!r}"
        assert len(repo.list_team_members(str(team.id))) == 1
