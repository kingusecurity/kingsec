"""Port for report generation and retrieval services.

This is the boundary between the API layer and the application layer for
report-related operations. The route layer depends on this abstraction;
a concrete implementation (in infrastructure) uses ``GenerateReport``,
``ReportRepository``, and the various renderers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

from kingsec.application.dto import RenderedReport


@dataclass(frozen=True)
class ReportGenerationResult:
    """Result of generating a report from a completed scan/assessment."""

    report_id: str
    status: str
    generated_at: datetime
    finding_count: int


class ReportServicePort(ABC):
    """Abstract contract for report generation and retrieval."""

    @abstractmethod
    def generate_report(self, scan_id: str) -> ReportGenerationResult:
        """Generate a report for the given scan/assessment ID."""

    @abstractmethod
    def get_report(self, report_id: str) -> dict:
        """Return the full report as a JSON-compatible dictionary."""

    @abstractmethod
    def get_summary(self, report_id: str) -> dict:
        """Return executive summary + risk summary as a dictionary."""

    @abstractmethod
    def get_formats(self, report_id: str) -> list[str]:
        """Return the list of available output format names."""

    @abstractmethod
    def render_report(self, report_id: str, format_name: str) -> RenderedReport:
        """Render a report in the given format and return the artifact."""
