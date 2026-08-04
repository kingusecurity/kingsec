"""Deployment-operations adapter.

Implements ``DeploymentOperationsPort`` by delegating to the 4 existing,
independently-tested services (``DiagnosticsCollector``, ``UpgradeService``,
``ReleaseAuditService``, ``ProductTelemetry``). No business logic lives here
- this is purely a port-boundary composition of already-working code.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kingsec.application.ports.outbound.deployment_operations import DeploymentOperationsPort
from kingsec.infrastructure.audit.release_audit import ReleaseAuditService
from kingsec.infrastructure.monitoring.diagnostics import DiagnosticsCollector
from kingsec.infrastructure.telemetry.product_telemetry import ProductTelemetry
from kingsec.infrastructure.upgrade.upgrade_service import UpgradeService


class DeploymentOperations(DeploymentOperationsPort):
    """Composes diagnostics, upgrade, release-audit and telemetry behind one port."""

    def __init__(
        self,
        diagnostics: DiagnosticsCollector,
        upgrade: UpgradeService,
        release_audit: ReleaseAuditService,
        telemetry: ProductTelemetry,
    ) -> None:
        self._diagnostics = diagnostics
        self._upgrade = upgrade
        self._release_audit = release_audit
        self._telemetry = telemetry

    # -- Diagnostics --

    def collect_system_info(self) -> dict[str, Any]:
        return self._diagnostics.collect_system_info()

    def collect_config_summary(self) -> dict[str, Any]:
        return self._diagnostics.collect_config_summary()

    def collect_all(self) -> dict[str, Any]:
        return self._diagnostics.collect_all()

    def create_bundle(self, output_dir: Path | None = None) -> Path:
        return self._diagnostics.create_bundle(output_dir=output_dir)

    # -- Upgrade --

    def create_plan(self, target_version: str) -> Any:
        return self._upgrade.create_plan(target_version)

    def create_backup(self) -> Path | None:
        return self._upgrade.create_backup()

    def set_installed_version(self, version: str) -> None:
        self._upgrade.set_installed_version(version)

    # -- Release audit --

    def generate_report(self) -> Any:
        return self._release_audit.generate_report()

    def record_upgrade(self, from_version: str, to_version: str, upgraded_by: str = "system") -> Any:
        return self._release_audit.record_upgrade(from_version, to_version, upgraded_by)

    def record_release(
        self,
        version: str,
        release_type: str = "patch",
        changes: tuple[str, ...] = (),
        breaking_changes: tuple[str, ...] = (),
        notes: str = "",
    ) -> Any:
        return self._release_audit.record_release(version, release_type, changes, breaking_changes, notes)

    # -- Telemetry --

    def get_summary(self, days: int = 30) -> dict[str, Any]:
        return self._telemetry.get_summary(days)
