"""Port for SIEM export integrations — application layer contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from kingsec.domain.integration import IntegrationType, SIEMBatchResult


class SIEMExportPort(ABC):
    """Abstract port for exporting findings to external SIEM systems."""

    @abstractmethod
    def export_findings(
        self,
        findings: list[dict[str, Any]],
        target_systems: list[IntegrationType] | None = None,
    ) -> list[SIEMBatchResult]:
        """Export findings to the given (or all configured) SIEM systems."""
