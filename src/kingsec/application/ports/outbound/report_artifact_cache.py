"""Port for removing rendered report artifacts when their assessment is deleted."""

from __future__ import annotations

from abc import ABC, abstractmethod


class ReportArtifactCachePort(ABC):
    """Lifecycle operations for report bytes stored outside the database."""

    @abstractmethod
    def delete_for_assessment(self, assessment_id: str) -> int:
        """Delete cached artifacts for ``assessment_id`` and return the count."""
