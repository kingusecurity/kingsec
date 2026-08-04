"""DeploymentOperations satisfies DeploymentOperationsPort and correctly
delegates to the 4 pre-existing services it composes.

Scoped to this: deployment_routes.py previously resolved 4 separate services
by their concrete infrastructure classes (an import-linter violation for an
adapter reaching across to sibling infrastructure modules). The 4 individual
ports were then consolidated into one ``DeploymentOperationsPort`` since all
4 concerns are consumed only from that one route file. This adapter must
prove it's a pure pass-through - no rewritten business logic.
"""

from __future__ import annotations

from pathlib import Path

from kingsec.application.ports.outbound import DeploymentOperationsPort
from kingsec.infrastructure.audit.release_audit import ReleaseAuditService
from kingsec.infrastructure.deployment.operations import DeploymentOperations
from kingsec.infrastructure.monitoring.diagnostics import DiagnosticsCollector
from kingsec.infrastructure.telemetry.product_telemetry import ProductTelemetry
from kingsec.infrastructure.upgrade.upgrade_service import UpgradeService


def _make_ops(tmp_path: Path) -> DeploymentOperations:
    return DeploymentOperations(
        diagnostics=DiagnosticsCollector(data_dir=tmp_path, app_version="9.9.9"),
        upgrade=UpgradeService(data_dir=tmp_path, current_version="9.9.9"),
        release_audit=ReleaseAuditService(data_dir=tmp_path),
        telemetry=ProductTelemetry(data_dir=tmp_path),
    )


class TestDeploymentOperationsIsAPort:
    def test_is_a_deployment_operations_port(self, tmp_path: Path) -> None:
        assert isinstance(_make_ops(tmp_path), DeploymentOperationsPort)


class TestDelegatesToDiagnostics:
    def test_collect_system_info_delegates(self, tmp_path: Path) -> None:
        ops = _make_ops(tmp_path)
        assert ops.collect_system_info() == DiagnosticsCollector(data_dir=tmp_path).collect_system_info()

    def test_create_bundle_delegates(self, tmp_path: Path) -> None:
        ops = _make_ops(tmp_path)
        bundle_path = ops.create_bundle(output_dir=tmp_path)
        assert bundle_path.is_file()
        assert bundle_path.suffix == ".zip"


class TestDelegatesToUpgrade:
    def test_create_plan_delegates(self, tmp_path: Path) -> None:
        ops = _make_ops(tmp_path)
        plan = ops.create_plan("10.0.0")
        assert plan.to_version == "10.0.0"

    def test_set_installed_version_delegates(self, tmp_path: Path) -> None:
        ops = _make_ops(tmp_path)
        ops.set_installed_version("10.0.0")
        assert (tmp_path / ".kingsec-version").read_text(encoding="utf-8") == "10.0.0"


class TestDelegatesToReleaseAudit:
    def test_record_release_delegates(self, tmp_path: Path) -> None:
        ops = _make_ops(tmp_path)
        entry = ops.record_release(version="1.2.3", release_type="minor")
        assert entry.version == "1.2.3"
        assert entry.release_type == "minor"

    def test_generate_report_reflects_recorded_release(self, tmp_path: Path) -> None:
        ops = _make_ops(tmp_path)
        ops.record_release(version="1.2.3")
        report = ops.generate_report()
        assert report.total_releases == 1


class TestDelegatesToTelemetry:
    def test_get_summary_delegates(self, tmp_path: Path) -> None:
        ops = _make_ops(tmp_path)
        summary = ops.get_summary(days=7)
        assert summary["period_days"] == 7
