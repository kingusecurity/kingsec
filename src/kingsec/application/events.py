"""Application-layer event types for lifecycle notifications.

These are NOT domain events (which would represent business-meaningful state
changes within the aggregate). These are infrastructure events used for
cross-cutting concerns like real-time streaming to clients.

The application layer defines WHAT events exist. The infrastructure layer
decides HOW they are delivered (SSE, WebSocket, logging, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True)
class AssessmentEvent:
    """A lifecycle event for an assessment."""

    event_type: str
    assessment_id: str
    state: str
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    progress: int | None = None
    message: str | None = None
    severity_counts: dict[str, int] | None = None

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dictionary."""
        result: dict = {
            "event_type": self.event_type,
            "assessment_id": self.assessment_id,
            "state": self.state,
            "timestamp": self.timestamp,
        }
        if self.progress is not None:
            result["progress"] = self.progress
        if self.message is not None:
            result["message"] = self.message
        if self.severity_counts is not None:
            result["severity_counts"] = self.severity_counts
        return result


# --- Event type constants ---------------------------------------------------

EVENT_ASSESSMENT_CREATED = "assessment.created"
EVENT_ASSESSMENT_RUNNING = "assessment.running"
EVENT_ASSESSMENT_COMPLETED = "assessment.completed"
EVENT_ASSESSMENT_FAILED = "assessment.failed"
EVENT_ASSESSMENT_CANCELLED = "assessment.cancelled"
EVENT_ASSESSMENT_DELETED = "assessment.deleted"
EVENT_REPORT_READY = "report.ready"
