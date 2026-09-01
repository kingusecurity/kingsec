"""Tests for the SQLAlchemy organization repository - KSEC-84-01, KSEC-86-01.

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

Phase 86 (KSEC-86-01): Phase 85 (KSEC-85-02) found and fixed the identical
"read -> mutate -> blind save()" lost-update pattern for schedules, and
flagged Organization.save()/Team.save_team() as sharing it (confirmed by
reading update_organization()/update_team() in organization_routes.py:
both read the aggregate, mutate name/slug or name/description on the SAME
object, then call save()/save_team() unconditionally). save()/save_team()
now optimistic-lock the update path exactly like
SqlAlchemyScheduleRepository.save() - see TestOrganizationVersioning/
TestTeamVersioning and the two genuine threaded concurrency tests below.
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kingsec.application.errors import OrganizationConflictError, TeamConflictError
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


class TestOrganizationVersioning:
    def test_new_organization_starts_at_version_one(self, repo: SQLAlchemyOrganizationRepository) -> None:
        org = _make_org(repo)
        assert repo.find_by_id(str(org.id)).version == 1

    def test_successful_update_increments_version(self, repo: SQLAlchemyOrganizationRepository) -> None:
        org = _make_org(repo)
        current = repo.find_by_id(str(org.id))
        current.name = "Acme Renamed"
        repo.save(current)

        assert repo.find_by_id(str(org.id)).version == 2

    def test_save_with_a_stale_version_raises_conflict_and_does_not_overwrite(
        self, repo: SQLAlchemyOrganizationRepository
    ) -> None:
        org = _make_org(repo)
        stale = repo.find_by_id(str(org.id))

        current = repo.find_by_id(str(org.id))
        current.name = "Acme Renamed"
        repo.save(current)  # version -> 2

        stale.name = "Attempted Stale Rename"
        with pytest.raises(OrganizationConflictError):
            repo.save(stale)

        final = repo.find_by_id(str(org.id))
        assert final.name == "Acme Renamed", "the winning (version-2) write was reverted by the rejected stale save"
        assert final.version == 2


class TestConcurrentOrganizationRename:
    """Thread A reads version 1, Thread B reads version 1 (via an explicit
    read barrier - see test_schedule_repository.py's
    TestConcurrentSameFieldRace docstring for why racing two bare threads
    through a fast read-then-write call does not reliably force this),
    both rename to different values, exactly one succeeds."""

    def test_two_concurrent_renames_from_the_same_read_one_wins_one_conflicts(self, session_factory) -> None:
        repo = SQLAlchemyOrganizationRepository(session_factory)
        org = _make_org(repo)

        read_barrier = threading.Barrier(2)
        results: list[str] = []
        lock = threading.Lock()

        def _rename(new_name: str) -> None:
            existing = repo.find_by_id(str(org.id))
            read_barrier.wait(timeout=5)  # both threads hold the SAME (version=1) read before either writes
            existing.name = new_name
            try:
                repo.save(existing)
                with lock:
                    results.append("ok")
            except OrganizationConflictError:
                with lock:
                    results.append("conflict")

        t1 = threading.Thread(target=_rename, args=("Renamed By A",))
        t2 = threading.Thread(target=_rename, args=("Renamed By B",))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        assert sorted(results) == ["conflict", "ok"], f"expected exactly one winner, one conflict: {results!r}"

        final = repo.find_by_id(str(org.id))
        assert final.version == 2, "exactly one successful write should have occurred, not zero or two"
        assert final.name in ("Renamed By A", "Renamed By B")


class TestTeamVersioning:
    def test_new_team_starts_at_version_one(self, repo: SQLAlchemyOrganizationRepository) -> None:
        org = _make_org(repo)
        team = Team(id=TeamId.generate(), organization_id=str(org.id), name="Red Team")
        repo.save_team(team)

        assert repo.find_team_by_id(str(team.id)).version == 1

    def test_successful_update_increments_version(self, repo: SQLAlchemyOrganizationRepository) -> None:
        org = _make_org(repo)
        team = Team(id=TeamId.generate(), organization_id=str(org.id), name="Red Team")
        repo.save_team(team)

        current = repo.find_team_by_id(str(team.id))
        current.name = "Blue Team"
        repo.save_team(current)

        assert repo.find_team_by_id(str(team.id)).version == 2

    def test_save_team_with_a_stale_version_raises_conflict_and_does_not_overwrite(
        self, repo: SQLAlchemyOrganizationRepository
    ) -> None:
        org = _make_org(repo)
        team = Team(id=TeamId.generate(), organization_id=str(org.id), name="Red Team")
        repo.save_team(team)
        stale = repo.find_team_by_id(str(team.id))

        current = repo.find_team_by_id(str(team.id))
        current.name = "Blue Team"
        repo.save_team(current)  # version -> 2

        stale.name = "Attempted Stale Rename"
        with pytest.raises(TeamConflictError):
            repo.save_team(stale)

        final = repo.find_team_by_id(str(team.id))
        assert final.name == "Blue Team", "the winning (version-2) write was reverted by the rejected stale save"
        assert final.version == 2


class TestConcurrentTeamFieldsRace:
    """A second scenario, on Team, racing DIFFERENT fields (name vs.
    description) from the same read - one succeeds, the other conflicts,
    and the loser's rejected write must never revert the winner's change."""

    def test_name_and_description_race_the_loser_never_reverts_the_winner(self, session_factory) -> None:
        repo = SQLAlchemyOrganizationRepository(session_factory)
        org = _make_org(repo)
        team = Team(id=TeamId.generate(), organization_id=str(org.id), name="Red Team", description="original")
        repo.save_team(team)

        read_barrier = threading.Barrier(2)
        results: dict[str, str] = {}
        lock = threading.Lock()

        def _rename() -> None:
            existing = repo.find_team_by_id(str(team.id))
            read_barrier.wait(timeout=5)
            existing.name = "Renamed Team"
            try:
                repo.save_team(existing)
                with lock:
                    results["rename"] = "ok"
            except TeamConflictError:
                with lock:
                    results["rename"] = "conflict"

        def _redescribe() -> None:
            existing = repo.find_team_by_id(str(team.id))
            read_barrier.wait(timeout=5)
            existing.description = "updated description"
            try:
                repo.save_team(existing)
                with lock:
                    results["describe"] = "ok"
            except TeamConflictError:
                with lock:
                    results["describe"] = "conflict"

        t1 = threading.Thread(target=_rename)
        t2 = threading.Thread(target=_redescribe)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        assert set(results.values()) == {"ok", "conflict"}, f"expected exactly one winner: {results!r}"

        final = repo.find_team_by_id(str(team.id))
        assert final.version == 2, "exactly one write should have been applied"

        if results["rename"] == "ok":
            assert final.name == "Renamed Team"
            assert final.description == "original"
        else:
            assert final.name == "Red Team"
            assert final.description == "updated description"
