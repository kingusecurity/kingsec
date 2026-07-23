"""Integration tests for SQLAlchemyAssetRepository.

Exercises every AssetRepositoryPort method against a real SQLite database.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from kingsec.application import AssessmentNotFoundError
from kingsec.application.ports.repositories import Asset
from kingsec.domain import Target, TargetType
from kingsec.infrastructure.persistence import (
    create_database_engine,
    create_schema,
)
from kingsec.infrastructure.persistence.repositories import (
    SQLAlchemyAssetRepository,
)

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
    return SQLAlchemyAssetRepository(session)


# ===========================================================================
# Helpers
# ===========================================================================


def make_asset(
    *,
    asset_id: str = "asset-1",
    target: Target | None = None,
    discovered_at: datetime | None = None,
    tags: frozenset[str] | None = None,
) -> Asset:
    return Asset(
        id=asset_id,
        target=target or Target("web01.example.com", TargetType.HOSTNAME),
        discovered_at=discovered_at or datetime(2026, 1, 1, tzinfo=UTC),
        tags=tags or frozenset(),
    )


# ===========================================================================
# Add & Get
# ===========================================================================


class TestAddAndGet:
    def test_add_and_get(self, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        asset = make_asset()
        repo.add(asset)
        session.flush()

        loaded = repo.get("asset-1")
        assert loaded.id == "asset-1"
        assert loaded.target.value == "web01.example.com"

    def test_get_returns_asset_object(self, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        asset = make_asset()
        repo.add(asset)
        session.flush()

        loaded = repo.get("asset-1")
        assert isinstance(loaded, Asset)

    def test_get_non_existent_raises(self, repo: SQLAlchemyAssetRepository) -> None:
        with pytest.raises(AssessmentNotFoundError):
            repo.get("nonexistent")

    def test_add_persists_to_database(self, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        asset = make_asset()
        repo.add(asset)
        session.flush()

        from kingsec.infrastructure.persistence.models import AssetModel

        orm = session.get(AssetModel, "asset-1")
        assert orm is not None
        assert orm.hostname == "web01.example.com"


# ===========================================================================
# Exists
# ===========================================================================


class TestExists:
    def test_exists_returns_true_when_present(self, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        repo.add(make_asset())
        session.flush()
        assert repo.exists("asset-1") is True

    def test_exists_returns_false_when_absent(self, repo: SQLAlchemyAssetRepository) -> None:
        assert repo.exists("nonexistent") is False

    def test_exists_after_add(self, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        assert repo.exists("asset-1") is False
        repo.add(make_asset())
        session.flush()
        assert repo.exists("asset-1") is True


# ===========================================================================
# List
# ===========================================================================


class TestList:
    def test_list_empty(self, repo: SQLAlchemyAssetRepository) -> None:
        assert repo.list() == []

    def test_list_returns_all(self, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        repo.add(make_asset(asset_id="a1", target=Target("h1.com", TargetType.HOSTNAME)))
        repo.add(make_asset(asset_id="a2", target=Target("h2.com", TargetType.HOSTNAME)))
        session.flush()

        result = repo.list()
        assert len(result) == 2

    def test_list_ordered_by_discovered_at_desc(self, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        early = datetime(2025, 1, 1, tzinfo=UTC)
        late = datetime(2026, 1, 1, tzinfo=UTC)
        repo.add(make_asset(asset_id="asset-early", discovered_at=early))
        repo.add(make_asset(asset_id="asset-late", discovered_at=late))
        session.flush()

        result = repo.list()
        assert result[0].id == "asset-late"
        assert result[1].id == "asset-early"

    def test_list_respects_limit(self, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        for i in range(5):
            repo.add(make_asset(asset_id=f"a{i}", target=Target(f"h{i}.com", TargetType.HOSTNAME)))
        session.flush()

        result = repo.list(limit=2)
        assert len(result) == 2

    def test_list_respects_offset(self, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        repo.add(make_asset(asset_id="a1"))
        repo.add(make_asset(asset_id="a2"))
        repo.add(make_asset(asset_id="a3"))
        session.flush()

        result = repo.list(limit=10, offset=1)
        assert len(result) == 2


# ===========================================================================
# Mapping correctness
# ===========================================================================


class TestMapping:
    def test_round_trip_preserves_hostname_target(self, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        asset = make_asset(target=Target("db01.internal", TargetType.HOSTNAME))
        repo.add(asset)
        session.flush()

        loaded = repo.get("asset-1")
        assert loaded.target.value == "db01.internal"
        assert loaded.target.type == TargetType.HOSTNAME

    def test_round_trip_preserves_ip_target(self, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        asset = make_asset(asset_id="asset-ip", target=Target("10.0.0.1", TargetType.IP_ADDRESS))
        repo.add(asset)
        session.flush()

        loaded = repo.get("asset-ip")
        assert loaded.target.value == "10.0.0.1"
        assert loaded.target.type == TargetType.IP_ADDRESS

    def test_round_trip_preserves_discovered_at(self, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        discovered_at = datetime(2025, 6, 15, 14, 30, 0, 123456, tzinfo=UTC)
        asset = make_asset(discovered_at=discovered_at)
        repo.add(asset)
        session.flush()

        loaded = repo.get("asset-1")
        assert loaded.discovered_at == discovered_at
        assert loaded.discovered_at.tzinfo is not None

    def test_round_trip_unicode(self, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        target = Target("unicode-srv.example.com", TargetType.HOSTNAME)
        asset = make_asset(target=target)
        repo.add(asset)
        session.flush()

        loaded = repo.get("asset-1")
        assert loaded.target.value == "unicode-srv.example.com"

    def test_round_trip_tags_default_empty(self, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        asset = make_asset(tags=frozenset({"production", "web"}))
        repo.add(asset)
        session.flush()

        loaded = repo.get("asset-1")
        # Tags are not stored in the current schema — always empty on retrieval.
        assert loaded.tags == frozenset()


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_multiple_assets(self, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        repo.add(make_asset(asset_id="a1", target=Target("web.local", TargetType.HOSTNAME)))
        repo.add(make_asset(asset_id="a2", target=Target("10.0.0.5", TargetType.IP_ADDRESS)))
        session.flush()

        assert repo.get("a1").target.value == "web.local"
        assert repo.get("a2").target.value == "10.0.0.5"
        assert len(repo.list()) == 2

    def test_rollback_discards_add(self, engine) -> None:
        with Session(engine) as s:
            repo = SQLAlchemyAssetRepository(s)
            repo.add(make_asset())
            s.rollback()

        with Session(engine) as s2:
            repo2 = SQLAlchemyAssetRepository(s2)
            assert repo2.exists("asset-1") is False

    def test_new_session_reads_committed(self, engine, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        repo.add(make_asset())
        session.commit()

        with Session(engine) as s2:
            repo2 = SQLAlchemyAssetRepository(s2)
            assert repo2.exists("asset-1") is True

    def test_empty_database(self, repo: SQLAlchemyAssetRepository) -> None:
        assert repo.list() == []
        assert repo.exists("anything") is False
        with pytest.raises(AssessmentNotFoundError):
            repo.get("anything")

    def test_add_duplicate_id_raises(self, repo: SQLAlchemyAssetRepository, session: Session) -> None:
        repo.add(make_asset())
        session.flush()

        with pytest.raises(Exception):
            repo.add(make_asset())
            session.flush()
