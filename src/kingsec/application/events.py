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
from typing import Any


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
    # Server-side only - deliberately never serialized in to_dict()/SSE
    # payloads. Used exclusively to scope event-bus delivery (KSEC-84-01:
    # the SSE endpoint previously broadcast every assessment's events,
    # including scan targets, to every authenticated user) to the
    # assessment's owner.
    owner_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dictionary."""
        result: dict[str, Any] = {
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
