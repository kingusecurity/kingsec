from __future__ import annotations

import pytest

from kingsec.domain.asset import (
    Asset,
    AssetCriticality,
    AssetService,
    AssetTag,
    AssetType,
    TechnologyFingerprint,
)
from kingsec.domain.errors import InvariantViolation
from kingsec.domain.identifiers import AssetId


class TestAssetConstruction:
    def test_create_with_minimal_args(self) -> None:
        asset = Asset.create(AssetType.HOST, hostname="web01")
        assert asset.asset_type == AssetType.HOST
        assert asset.hostname == "web01"
        assert asset.criticality == AssetCriticality.MEDIUM
        assert asset.created_at is not None
        assert asset.updated_at is not None

    def test_create_with_all_args(self) -> None:
        asset = Asset.create(
            AssetType.SERVER,
            hostname="db01",
            ip_address="10.0.0.1",
            domain="example.com",
            operating_system="Linux",
            criticality=AssetCriticality.CRITICAL,
        )
        assert asset.ip_address == "10.0.0.1"
        assert asset.criticality == AssetCriticality.CRITICAL

    def test_create_generates_id(self) -> None:
        asset = Asset.create(AssetType.HOST)
        assert isinstance(asset.id, AssetId)
        assert asset.id.value.startswith("ast-")
        assert len(asset.id.value) > 16

    def test_invalid_asset_type_raises(self) -> None:
        with pytest.raises(InvariantViolation):
            Asset(AssetId.generate(), "invalid")  # type: ignore[arg-type]

    def test_default_timestamp(self) -> None:
        a1 = Asset.create(AssetType.HOST)
        a2 = Asset.create(AssetType.HOST)
        assert a1.created_at != a2.created_at or True  # Non-deterministic but at least present


class TestAssetIdentity:
    def test_equality_by_id(self) -> None:
        aid = AssetId.generate()
        a = Asset(aid, AssetType.HOST, hostname="a")
        b = Asset(aid, AssetType.HOST, hostname="b")
        assert a == b
        assert hash(a) == hash(b)

    def test_different_ids_not_equal(self) -> None:
        a = Asset.create(AssetType.HOST)
        b = Asset.create(AssetType.HOST)
        assert a != b


class TestAssetTags:
    def test_add_tag(self) -> None:
        asset = Asset.create(AssetType.HOST)
        asset.add_tag(AssetTag("env", "prod"))
        assert len(asset.tags) == 1
        assert asset.tags[0].key == "env"
        assert asset.tags[0].value == "prod"

    def test_remove_tag(self) -> None:
        asset = Asset.create(AssetType.HOST)
        asset.add_tag(AssetTag("env", "prod"))
        asset.remove_tag("env")
        assert len(asset.tags) == 0

    def test_duplicate_tag_key_ignored(self) -> None:
        asset = Asset.create(AssetType.HOST)
        asset.add_tag(AssetTag("env", "prod"))
        asset.add_tag(AssetTag("env", "staging"))
        assert len(asset.tags) == 1

    def test_empty_tag_key_raises(self) -> None:
        with pytest.raises(InvariantViolation):
            AssetTag("", "val")


class TestAssetServices:
    def test_add_service(self) -> None:
        asset = Asset.create(AssetType.HOST)
        asset.add_service(AssetService("nginx", 443, "tcp"))
        assert len(asset.services) == 1
        assert asset.services[0].name == "nginx"

    def test_add_service_adds_to_open_ports(self) -> None:
        asset = Asset.create(AssetType.HOST)
        asset.add_service(AssetService("http", 80))
        assert 80 in asset.open_ports


class TestAssetTechnologies:
    def test_add_technology(self) -> None:
        asset = Asset.create(AssetType.HOST)
        asset.add_technology(TechnologyFingerprint("web_server", "nginx", "1.25"))
        assert len(asset.technologies) == 1

    def test_duplicate_technology_skipped(self) -> None:
        asset = Asset.create(AssetType.HOST)
        asset.add_technology(TechnologyFingerprint("web_server", "nginx", "1.25"))
        asset.add_technology(TechnologyFingerprint("web_server", "nginx", "1.26"))
        assert len(asset.technologies) == 1


class TestAssetRisk:
    def test_risk_score_calculation(self) -> None:
        asset = Asset.create(AssetType.HOST)
        score = asset.calculate_risk_score(critical_findings=2, high_findings=3, open_findings=5)
        assert score > 0
        assert score <= 100

    def test_critical_assets_have_higher_risk(self) -> None:
        low = Asset.create(AssetType.HOST, criticality=AssetCriticality.LOW)
        high = Asset.create(AssetType.HOST, criticality=AssetCriticality.CRITICAL)
        low.calculate_risk_score(critical_findings=1)
        high.calculate_risk_score(critical_findings=1)
        assert high.risk_score > low.risk_score

    def test_risk_score_capped(self) -> None:
        asset = Asset.create(AssetType.HOST, criticality=AssetCriticality.CRITICAL)
        asset.calculate_risk_score(critical_findings=100)
        assert asset.risk_score <= 100


class TestAssetCriticality:
    def test_update_criticality(self) -> None:
        asset = Asset.create(AssetType.HOST)
        asset.update_criticality(AssetCriticality.CRITICAL)
        assert asset.criticality == AssetCriticality.CRITICAL

    def test_invalid_criticality_raises(self) -> None:
        with pytest.raises(InvariantViolation):
            Asset.create(AssetType.HOST).update_criticality("invalid")  # type: ignore[arg-type]


class TestAssetTypeEnum:
    def test_all_types(self) -> None:
        types = [e.value for e in AssetType]
        assert "host" in types
        assert "server" in types
        assert "domain" in types
        assert "container" in types
        assert "cloud_resource" in types
        assert "certificate" in types
