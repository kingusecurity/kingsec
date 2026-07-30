from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from kingsec.application.errors import AssetNotFoundError
from kingsec.application.ports.asset_inventory import (
    AssetDetail,
    AssetDiscoveryPort,
    AssetFilter,
    AssetInventoryRepositoryPort,
    AssetSummary,
    TechnologyFingerprintPort,
)
from kingsec.domain.asset import (
    Asset,
    AssetCriticality,
    AssetHistoryEntry,
    AssetRelationship,
    AssetTag,
    AssetType,
    TechnologyFingerprint,
)
from kingsec.domain.errors import InvariantViolation


class AssetInventoryService:
    """Application service for the Asset Inventory module."""

    def __init__(
        self,
        repo: AssetInventoryRepositoryPort,
        technology_fingerprinter: TechnologyFingerprintPort | None = None,
        asset_discovery: AssetDiscoveryPort | None = None,
    ) -> None:
        self._repo = repo
        self._fingerprinter = technology_fingerprinter
        self._discovery = asset_discovery

    # --- CRUD ---

    def create_asset(
        self,
        asset_type: AssetType,
        *,
        hostname: str | None = None,
        ip_address: str | None = None,
        **kwargs: Any,
    ) -> Asset:
        asset = Asset.create(asset_type, hostname=hostname, ip_address=ip_address, **kwargs)
        self._repo.save(asset)
        self._repo.save_history(
            AssetHistoryEntry(
                asset_id=str(asset.id),
                event_type="created",
                description=f"Asset created: {asset_type.value}",
                timestamp=datetime.now(UTC).isoformat(),
            )
        )
        return asset

    def get_asset(self, asset_id: str) -> Asset:
        try:
            return self._repo.get(asset_id)
        except AssetNotFoundError:
            raise AssetNotFoundError(f"Asset not found: {asset_id}")

    def get_asset_detail(self, asset_id: str) -> AssetDetail:
        asset = self._repo.get(asset_id)
        relationships = self._repo.get_relationships(asset_id)
        history = self._repo.get_history(asset_id)
        finding_ids = self._repo.get_finding_ids(asset_id)
        return AssetDetail(
            asset=asset,
            relationships=relationships,
            history=history,
            finding_count=len(finding_ids),
        )

    def update_asset(self, asset_id: str, updates: dict[str, Any]) -> Asset:
        asset = self._repo.get(asset_id)
        changes: list[str] = []
        for key, value in updates.items():
            prev = _get_asset_attr(asset, key)
            if prev != value:
                _set_asset_attr(asset, key, value)
                changes.append(f"{key}: {prev!r} -> {value!r}")
        if changes:
            self._repo.save(asset)
            self._repo.save_history(
                AssetHistoryEntry(
                    asset_id=asset_id,
                    event_type="updated",
                    description="; ".join(changes),
                    timestamp=datetime.now(UTC).isoformat(),
                )
            )
        return asset

    def delete_asset(self, asset_id: str) -> None:
        self._repo.get(asset_id)
        self._repo.delete(asset_id)

    # --- Listing & search ---

    def list_assets(
        self,
        filter_: AssetFilter | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Asset]:
        return self._repo.fetch_all(filter_, limit=limit, offset=offset)

    def count_assets(self, filter_: AssetFilter | None = None) -> int:
        return self._repo.count(filter_)

    def search_assets(self, query: str, *, limit: int = 20) -> list[Asset]:
        return self._repo.search(query, limit=limit)

    def get_asset_summary(self) -> AssetSummary:
        return self._repo.summary()

    # --- Tags ---

    def add_tag(self, asset_id: str, key: str, value: str) -> Asset:
        asset = self._repo.get(asset_id)
        asset.add_tag(AssetTag(key=key, value=value))
        self._repo.save(asset)
        self._repo.save_history(
            AssetHistoryEntry(
                asset_id=asset_id,
                event_type="tag_added",
                description=f"Tag added: {key}={value}",
                timestamp=datetime.now(UTC).isoformat(),
            )
        )
        return asset

    def remove_tag(self, asset_id: str, key: str) -> Asset:
        asset = self._repo.get(asset_id)
        asset.remove_tag(key)
        self._repo.save(asset)
        self._repo.save_history(
            AssetHistoryEntry(
                asset_id=asset_id,
                event_type="tag_removed",
                description=f"Tag removed: {key}",
                timestamp=datetime.now(UTC).isoformat(),
            )
        )
        return asset

    # --- Services & ports ---

    def add_service(self, asset_id: str, name: str, port: int, protocol: str = "tcp", **extra: Any) -> Asset:
        from kingsec.domain.asset import AssetService

        asset = self._repo.get(asset_id)
        svc = AssetService(name=name, port=port, protocol=protocol, version=extra.get("version"), state=extra.get("state", "open"))
        asset.add_service(svc)
        self._repo.save(asset)
        return asset

    def add_technology(self, asset_id: str, tech_type: str, name: str, **extra: Any) -> Asset:
        asset = self._repo.get(asset_id)
        tech = TechnologyFingerprint(
            technology_type=tech_type,
            name=name,
            version=extra.get("version"),
            vendor=extra.get("vendor"),
            confidence=extra.get("confidence", 1.0),
        )
        asset.add_technology(tech)
        self._repo.save(asset)
        return asset

    # --- Relationships ---

    def add_relationship(self, source_id: str, target_id: str, rel_type: str, metadata: dict[str, Any] | None = None) -> AssetRelationship:
        rel = AssetRelationship(
            source_asset_id=source_id,
            target_asset_id=target_id,
            relationship_type=rel_type,
            metadata=metadata or {},
        )
        self._repo.save_relationship(rel)
        self._repo.save_history(
            AssetHistoryEntry(
                asset_id=source_id,
                event_type="relationship_added",
                description=f"Relationship {rel_type} -> {target_id}",
                timestamp=datetime.now(UTC).isoformat(),
            )
        )
        return rel

    def get_relationships(self, asset_id: str) -> list[AssetRelationship]:
        return self._repo.get_relationships(asset_id)

    def remove_relationship(self, source_id: str, target_id: str, rel_type: str) -> None:
        self._repo.delete_relationship(source_id, target_id, rel_type)

    # --- Risk ---

    def recalculate_risk(self, asset_id: str, critical_findings: int = 0, high_findings: int = 0, open_findings: int = 0) -> Asset:
        asset = self._repo.get(asset_id)
        asset.calculate_risk_score(critical_findings, high_findings, open_findings)
        self._repo.save(asset)
        return asset

    def update_criticality(self, asset_id: str, criticality: str) -> Asset:
        crit = AssetCriticality(criticality)
        asset = self._repo.get(asset_id)
        prev = asset.criticality.value
        asset.update_criticality(crit)
        self._repo.save(asset)
        self._repo.save_history(
            AssetHistoryEntry(
                asset_id=asset_id,
                event_type="criticality_changed",
                description=f"Criticality: {prev} -> {criticality}",
                timestamp=datetime.now(UTC).isoformat(),
            )
        )
        return asset

    # --- Discovery ---

    def discover_and_register(self, target: str, asset_type: AssetType) -> list[Asset]:
        if self._discovery is None:
            raise InvariantViolation("Asset discovery port not configured")
        raw = self._discovery.discover(target, asset_type)
        assets: list[Asset] = []
        for item in raw:
            asset = Asset.create(asset_type, **item)
            self._repo.save(asset)
            assets.append(asset)
        return assets

    def fingerprint_technologies(self, hostname: str, ip: str | None = None, port: int | None = None) -> list[TechnologyFingerprint]:
        if self._fingerprinter is None:
            raise InvariantViolation("Technology fingerprinting port not configured")
        raw = self._fingerprinter.fingerprint(hostname, ip, port)
        return [TechnologyFingerprint(**t) for t in raw]

    # --- History ---

    def get_history(self, asset_id: str, *, limit: int = 50) -> list[AssetHistoryEntry]:
        return self._repo.get_history(asset_id, limit=limit)


def _get_asset_attr(asset: Asset, name: str) -> Any:
    return getattr(asset, name, None)


def _set_asset_attr(asset: Asset, name: str, value: Any) -> None:
    private = f"_{name}"
    if hasattr(asset, private):
        setattr(asset, private, value)
    elif hasattr(asset, name):
        setattr(asset, name, value)
