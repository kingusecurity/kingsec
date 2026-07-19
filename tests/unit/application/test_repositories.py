from __future__ import annotations

import inspect
from datetime import datetime, timezone

import pytest

from kingsec.application.ports.repositories import (
    Asset,
    AssetRepositoryPort,
    JobRepositoryPort,
    ScanRepositoryPort,
)
from kingsec.domain import ScannerResult, Target, TargetType, ScannerId


# ===========================================================================
# Asset dataclass
# ===========================================================================


class TestAssetDataclass:
    def test_asset_is_frozen(self) -> None:
        asset = Asset(
            id="asset-1",
            target=Target("10.0.0.1", TargetType.IP_ADDRESS),
            discovered_at=datetime.now(timezone.utc),
        )
        with pytest.raises(AttributeError):
            asset.id = "changed"  # type: ignore[misc]

    def test_asset_default_tags(self) -> None:
        asset = Asset(
            id="asset-1",
            target=Target("example.com", TargetType.HOSTNAME),
            discovered_at=datetime.now(timezone.utc),
        )
        assert asset.tags == frozenset()

    def test_asset_with_tags(self) -> None:
        asset = Asset(
            id="asset-1",
            target=Target("10.0.0.1", TargetType.IP_ADDRESS),
            discovered_at=datetime.now(timezone.utc),
            tags=frozenset({"production", "web"}),
        )
        assert "production" in asset.tags
        assert "web" in asset.tags


# ===========================================================================
# Port abstractness — each port must be uninstantiable
# ===========================================================================


class TestScanRepositoryPortIsAbstract:
    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            ScanRepositoryPort()  # type: ignore[abstract]

    def test_incomplete_implementation_raises(self) -> None:
        class Partial(ScanRepositoryPort):
            def save(self, scan_id: str, result: ScannerResult) -> None:
                pass

        with pytest.raises(TypeError):
            Partial()  # type: ignore[abstract]

    def test_complete_implementation_can_instantiate(self) -> None:
        class Full(ScanRepositoryPort):
            def save(self, scan_id: str, result: ScannerResult) -> None:
                pass
            def get(self, scan_id: str) -> ScannerResult:
                raise NotImplementedError
            def exists(self, scan_id: str) -> bool:
                return False
            def delete(self, scan_id: str) -> None:
                pass

        instance = Full()
        assert isinstance(instance, ScanRepositoryPort)


class TestJobRepositoryPortIsAbstract:
    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            JobRepositoryPort()  # type: ignore[abstract]

    def test_incomplete_implementation_raises(self) -> None:
        class Partial(JobRepositoryPort):
            def save(self, job: object) -> None:
                pass

        with pytest.raises(TypeError):
            Partial()  # type: ignore[abstract]

    def test_complete_implementation_can_instantiate(self) -> None:
        class Full(JobRepositoryPort):
            def save(self, job: object) -> None:
                pass
            def get(self, job_id: str) -> object:
                raise NotImplementedError
            def list(self, *, limit: int = 50, offset: int = 0) -> list:
                return []
            def exists(self, job_id: str) -> bool:
                return False

        instance = Full()
        assert isinstance(instance, JobRepositoryPort)


class TestAssetRepositoryPortIsAbstract:
    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            AssetRepositoryPort()  # type: ignore[abstract]

    def test_incomplete_implementation_raises(self) -> None:
        class Partial(AssetRepositoryPort):
            def add(self, asset: Asset) -> None:
                pass

        with pytest.raises(TypeError):
            Partial()  # type: ignore[abstract]

    def test_complete_implementation_can_instantiate(self) -> None:
        class Full(AssetRepositoryPort):
            def add(self, asset: Asset) -> None:
                pass
            def get(self, asset_id: str) -> Asset:
                raise NotImplementedError
            def list(self, *, limit: int = 50, offset: int = 0) -> list[Asset]:
                return []
            def exists(self, asset_id: str) -> bool:
                return False

        instance = Full()
        assert isinstance(instance, AssetRepositoryPort)


# ===========================================================================
# Method signatures — verify expected parameters exist
# ===========================================================================


class TestScanRepositoryPortSignatures:
    def test_save_takes_scan_id_and_scanner_result(self) -> None:
        sig = inspect.signature(ScanRepositoryPort.save)
        params = list(sig.parameters.keys())
        assert "scan_id" in params
        assert "result" in params

    def test_get_takes_scan_id(self) -> None:
        sig = inspect.signature(ScanRepositoryPort.get)
        assert "scan_id" in sig.parameters

    def test_exists_takes_scan_id(self) -> None:
        sig = inspect.signature(ScanRepositoryPort.exists)
        assert "scan_id" in sig.parameters

    def test_delete_takes_scan_id(self) -> None:
        sig = inspect.signature(ScanRepositoryPort.delete)
        assert "scan_id" in sig.parameters


class TestJobRepositoryPortSignatures:
    def test_save_takes_job(self) -> None:
        sig = inspect.signature(JobRepositoryPort.save)
        assert "job" in sig.parameters

    def test_get_takes_job_id(self) -> None:
        sig = inspect.signature(JobRepositoryPort.get)
        assert "job_id" in sig.parameters

    def test_list_has_limit_and_offset(self) -> None:
        sig = inspect.signature(JobRepositoryPort.list)
        assert "limit" in sig.parameters
        assert "offset" in sig.parameters

    def test_exists_takes_job_id(self) -> None:
        sig = inspect.signature(JobRepositoryPort.exists)
        assert "job_id" in sig.parameters


class TestAssetRepositoryPortSignatures:
    def test_add_takes_asset(self) -> None:
        sig = inspect.signature(AssetRepositoryPort.add)
        assert "asset" in sig.parameters

    def test_get_takes_asset_id(self) -> None:
        sig = inspect.signature(AssetRepositoryPort.get)
        assert "asset_id" in sig.parameters

    def test_list_has_limit_and_offset(self) -> None:
        sig = inspect.signature(AssetRepositoryPort.list)
        assert "limit" in sig.parameters
        assert "offset" in sig.parameters

    def test_exists_takes_asset_id(self) -> None:
        sig = inspect.signature(AssetRepositoryPort.exists)
        assert "asset_id" in sig.parameters


# ===========================================================================
# Exports — verify new ports are importable from application.ports
# ===========================================================================


class TestExports:
    def test_scan_repository_port_exported(self) -> None:
        from kingsec.application.ports import ScanRepositoryPort  # noqa: F811
        assert ScanRepositoryPort is not None

    def test_job_repository_port_exported(self) -> None:
        from kingsec.application.ports import JobRepositoryPort  # noqa: F811
        assert JobRepositoryPort is not None

    def test_asset_repository_port_exported(self) -> None:
        from kingsec.application.ports import AssetRepositoryPort  # noqa: F811
        assert AssetRepositoryPort is not None

    def test_asset_dataclass_exported(self) -> None:
        from kingsec.application.ports.repositories import Asset  # noqa: F811
        assert Asset is not None
