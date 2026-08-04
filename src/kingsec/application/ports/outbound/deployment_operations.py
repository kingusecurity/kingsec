"""Port for deployment operations — application layer contract.

Covers 4 concerns previously split across 4 separate ports (diagnostics,
upgrade, release audit, telemetry). Consolidated into one interface because
all 4 are consumed only from ``deployment_routes.py`` — there was no second
caller to justify independent abstractions.

``create_plan``, ``generate_report``, ``record_upgrade`` and
``record_release`` return ``Any`` (rather than the infrastructure-owned
dataclasses) so this port stays free of infrastructure imports; callers only
use them for attribute/duck-typed access.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class DeploymentOperationsPort(ABC):
    """Abstract port for diagnostics, upgrades, release audit and telemetry."""

    # -- Diagnostics --

    @abstractmethod
    def collect_system_info(self) -> dict[str, Any]:
        """Collect basic system information."""

    @abstractmethod
    def collect_config_summary(self) -> dict[str, Any]:
        """Collect a non-sensitive configuration summary."""

    @abstractmethod
    def collect_all(self) -> dict[str, Any]:
        """Collect all diagnostic data."""

    @abstractmethod
    def create_bundle(self, output_dir: Path | None = None) -> Path:
        """Create a diagnostics bundle file and return its path."""

    # -- Upgrade --

    @abstractmethod
    def create_plan(self, target_version: str) -> Any:
        """Create a full upgrade plan with pre-flight checks."""

    @abstractmethod
    def create_backup(self) -> Path | None:
        """Create a backup of the database before upgrade."""

    @abstractmethod
    def set_installed_version(self, version: str) -> None:
        """Write the installed version to disk."""

    # -- Release audit --

    @abstractmethod
    def generate_report(self) -> Any:
        """Generate a complete release audit report."""

    @abstractmethod
    def record_upgrade(self, from_version: str, to_version: str, upgraded_by: str = "system") -> Any:
        """Record an upgrade event."""

    @abstractmethod
    def record_release(
        self,
        version: str,
        release_type: str = "patch",
        changes: tuple[str, ...] = (),
        breaking_changes: tuple[str, ...] = (),
        notes: str = "",
    ) -> Any:
        """Record a new release."""

    # -- Telemetry --

    @abstractmethod
    def get_summary(self, days: int = 30) -> dict[str, Any]:
        """Get a summary of telemetry data for the past N days."""
