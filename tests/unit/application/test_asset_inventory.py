from __future__ import annotations

import pytest

from kingsec.application.ports.asset_inventory import (
    AssetFilter,
    AssetInventoryRepositoryPort,
    AssetSummary,
)
from kingsec.application.services.asset_inventory import AssetInventoryService
from kingsec.domain.asset import (
    Asset,
    AssetCriticality,
    AssetHistoryEntry,
    AssetRelationship,
    AssetType,
)


class InMemoryAssetInventoryRepository(AssetInventoryRepositoryPort):
    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}
        self._relationships: list[AssetRelationship] = []
        self._history: list[AssetHistoryEntry] = []
        self._finding_links: dict[str, list[str]] = {}

    def save(self, asset: Asset) -> None:
        self._assets[str(asset.id)] = asset

    def get(self, asset_id: str) -> Asset:
        if asset_id not in self._assets:
            from kingsec.application.errors import AssetNotFoundError
            raise AssetNotFoundError(f"Asset not found: {asset_id}")
        return self._assets[asset_id]

    def delete(self, asset_id: str) -> None:
        self._assets.pop(asset_id, None)

    def fetch_all(self, filter_: AssetFilter | None = None, *, limit: int = 50, offset: int = 0) -> list[Asset]:
        items = list(self._assets.values())
        if filter_ and filter_.asset_type:
            items = [a for a in items if a.asset_type == filter_.asset_type]
        if filter_ and filter_.criticality:
            items = [a for a in items if a.criticality.value == filter_.criticality]
        return items[offset:offset + limit]

    def count(self, filter_: AssetFilter | None = None) -> int:
        return len(self.fetch_all(filter_))

    def summary(self) -> AssetSummary:
        return AssetSummary(
            total=len(self._assets),
            by_type={t.value: 1 for t in AssetType},
            by_criticality={c.value: 0 for c in AssetCriticality},
            by_risk_range={"none": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
            total_open_findings=0,
            total_critical_findings=0,
            total_high_findings=0,
            total_relationships=len(self._relationships),
        )

    def search(self, query: str, *, limit: int = 20) -> list[Asset]:
        q = query.lower()
        return [a for a in self._assets.values() if a.hostname and q in a.hostname.lower()][:limit]

    def save_relationship(self, rel: AssetRelationship) -> None:
        self._relationships.append(rel)

    def get_relationships(self, asset_id: str) -> list[AssetRelationship]:
        return [r for r in self._relationships if r.source_asset_id == asset_id or r.target_asset_id == asset_id]

    def delete_relationship(self, source_id: str, target_id: str, rel_type: str) -> None:
        self._relationships = [
            r for r in self._relationships
            if not (r.source_asset_id == source_id and r.target_asset_id == target_id and r.relationship_type == rel_type)
        ]

    def save_history(self, entry: AssetHistoryEntry) -> None:
        self._history.append(entry)

    def get_history(self, asset_id: str, *, limit: int = 50) -> list[AssetHistoryEntry]:
        return [h for h in self._history if h.asset_id == asset_id][:limit]

    def get_by_hostname(self, hostname: str) -> Asset | None:
        for a in self._assets.values():
            if a.hostname == hostname:
                return a
        return None

    def get_by_ip(self, ip: str) -> Asset | None:
        for a in self._assets.values():
            if a.ip_address == ip:
                return a
        return None

    def get_by_domain(self, domain: str) -> Asset | None:
        for a in self._assets.values():
            if a.domain == domain:
                return a
        return None

    def add_finding_to_asset(self, asset_id: str, finding_id: str) -> None:
        self._finding_links.setdefault(asset_id, []).append(finding_id)

    def get_finding_ids(self, asset_id: str) -> list[str]:
        return self._finding_links.get(asset_id, [])


@pytest.fixture
def repo() -> InMemoryAssetInventoryRepository:
    return InMemoryAssetInventoryRepository()


@pytest.fixture
def svc(repo: InMemoryAssetInventoryRepository) -> AssetInventoryService:
    return AssetInventoryService(repo)


class TestCreateAsset:
    def test_create_host(self, svc: AssetInventoryService, repo: InMemoryAssetInventoryRepository) -> None:
        asset = svc.create_asset(AssetType.HOST, hostname="web01", ip_address="10.0.0.1")
        assert asset.hostname == "web01"
        assert asset.ip_address == "10.0.0.1"
        assert asset.asset_type == AssetType.HOST
        assert repo.get(str(asset.id)) is not None

    def test_create_records_history(self, svc: AssetInventoryService, repo: InMemoryAssetInventoryRepository) -> None:
        asset = svc.create_asset(AssetType.SERVER)
        history = repo.get_history(str(asset.id))
        assert len(history) == 1
        assert history[0].event_type == "created"

    def test_create_multiple_assets(self, svc: AssetInventoryService) -> None:
        a1 = svc.create_asset(AssetType.HOST, hostname="web01")
        a2 = svc.create_asset(AssetType.HOST, hostname="web02")
        assert a1 != a2
        assert svc.count_assets() == 2


class TestGetAsset:
    def test_get_existing(self, svc: AssetInventoryService) -> None:
        created = svc.create_asset(AssetType.HOST, hostname="db01")
        fetched = svc.get_asset(str(created.id))
        assert fetched.id == created.id

    def test_get_not_found(self, svc: AssetInventoryService) -> None:
        from kingsec.application.errors import AssetNotFoundError
        with pytest.raises(AssetNotFoundError):
            svc.get_asset("nonexistent")


class TestUpdateAsset:
    def test_update_field(self, svc: AssetInventoryService) -> None:
        asset = svc.create_asset(AssetType.HOST, hostname="old")
        svc.update_asset(str(asset.id), {"hostname": "new"})
        updated = svc.get_asset(str(asset.id))
        assert updated.hostname == "new"

    def test_update_records_history(self, svc: AssetInventoryService, repo: InMemoryAssetInventoryRepository) -> None:
        asset = svc.create_asset(AssetType.HOST, owner="alice")
        svc.update_asset(str(asset.id), {"owner": "bob"})
        history = repo.get_history(str(asset.id))
        events = [h.event_type for h in history]
        assert "updated" in events


class TestDeleteAsset:
    def test_delete_existing(self, svc: AssetInventoryService, repo: InMemoryAssetInventoryRepository) -> None:
        asset = svc.create_asset(AssetType.HOST)
        svc.delete_asset(str(asset.id))
        assert repo.count() == 0

    def test_delete_not_found(self, svc: AssetInventoryService) -> None:
        from kingsec.application.errors import AssetNotFoundError
        with pytest.raises(AssetNotFoundError):
            svc.delete_asset("nonexistent")


class TestListSearch:
    def test_list_all(self, svc: AssetInventoryService) -> None:
        svc.create_asset(AssetType.HOST, hostname="a")
        svc.create_asset(AssetType.SERVER, hostname="b")
        assert len(svc.list_assets()) == 2

    def test_filter_by_type(self, svc: AssetInventoryService) -> None:
        svc.create_asset(AssetType.HOST)
        svc.create_asset(AssetType.SERVER)
        filter_ = AssetFilter(asset_type=AssetType.HOST)
        result = svc.list_assets(filter_)
        assert len(result) == 1
        assert result[0].asset_type == AssetType.HOST

    def test_search_by_hostname(self, svc: AssetInventoryService) -> None:
        svc.create_asset(AssetType.HOST, hostname="web-prod-01")
        svc.create_asset(AssetType.HOST, hostname="db-staging-01")
        result = svc.search_assets("web")
        assert len(result) == 1
        assert result[0].hostname == "web-prod-01"


class TestTags:
    def test_add_tag(self, svc: AssetInventoryService) -> None:
        asset = svc.create_asset(AssetType.HOST)
        svc.add_tag(str(asset.id), "env", "prod")
        updated = svc.get_asset(str(asset.id))
        assert len(updated.tags) == 1
        assert updated.tags[0].key == "env"

    def test_remove_tag(self, svc: AssetInventoryService) -> None:
        asset = svc.create_asset(AssetType.HOST)
        svc.add_tag(str(asset.id), "env", "prod")
        svc.remove_tag(str(asset.id), "env")
        updated = svc.get_asset(str(asset.id))
        assert len(updated.tags) == 0

    def test_tag_records_history(self, svc: AssetInventoryService, repo: InMemoryAssetInventoryRepository) -> None:
        asset = svc.create_asset(AssetType.HOST)
        svc.add_tag(str(asset.id), "env", "prod")
        history = repo.get_history(str(asset.id))
        assert any(h.event_type == "tag_added" for h in history)


class TestRelationships:
    def test_add_relationship(self, svc: AssetInventoryService) -> None:
        a1 = svc.create_asset(AssetType.HOST, hostname="web")
        a2 = svc.create_asset(AssetType.SERVER, hostname="db")
        svc.add_relationship(str(a1.id), str(a2.id), "connects_to")
        rels = svc.get_relationships(str(a1.id))
        assert len(rels) == 1
        assert rels[0].relationship_type == "connects_to"

    def test_remove_relationship(self, svc: AssetInventoryService) -> None:
        a1 = svc.create_asset(AssetType.HOST)
        a2 = svc.create_asset(AssetType.HOST)
        svc.add_relationship(str(a1.id), str(a2.id), "connected")
        svc.remove_relationship(str(a1.id), str(a2.id), "connected")
        assert len(svc.get_relationships(str(a1.id))) == 0


class TestRisk:
    def test_recalculate_risk(self, svc: AssetInventoryService) -> None:
        asset = svc.create_asset(AssetType.HOST)
        svc.recalculate_risk(str(asset.id), critical_findings=1, high_findings=2)
        updated = svc.get_asset(str(asset.id))
        assert updated.risk_score > 0

    def test_update_criticality(self, svc: AssetInventoryService) -> None:
        asset = svc.create_asset(AssetType.HOST)
        svc.update_criticality(str(asset.id), "critical")
        updated = svc.get_asset(str(asset.id))
        assert updated.criticality == AssetCriticality.CRITICAL


class TestHistory:
    def test_get_history(self, svc: AssetInventoryService) -> None:
        asset = svc.create_asset(AssetType.HOST)
        svc.add_tag(str(asset.id), "env", "test")
        svc.update_criticality(str(asset.id), "high")
        history = svc.get_history(str(asset.id))
        assert len(history) >= 2

    def test_history_timestamps(self, svc: AssetInventoryService) -> None:
        asset = svc.create_asset(AssetType.HOST)
        history = svc.get_history(str(asset.id))
        assert len(history) == 1
        assert history[0].timestamp is not None
