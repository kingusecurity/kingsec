"""Port for enterprise audit event persistence."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from kingsec.domain.audit_event import AuditEvent, AuditEventId


class AuditEventRepository(ABC):
    """Abstract port for audit event storage and retrieval.

    Append-only by contract: implementations MUST NOT update or delete.
    """

    @abstractmethod
    def save(self, event: AuditEvent) -> None:
        """Persist an audit event.

        Args:
            event: The immutable audit event to record.
        """

    @abstractmethod
    def find_by_id(self, event_id: AuditEventId) -> AuditEvent | None:
        """Look up a single audit event by its ID.

        Args:
            event_id: The unique event identifier.

        Returns:
            The AuditEvent if found, None otherwise.
        """

    @abstractmethod
    def search(
        self,
        *,
        actor_id: str | None = None,
        action: str | None = None,
        severity: str | None = None,
        outcome: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 50,
        offset: int = 0,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
    ) -> tuple[list[AuditEvent], int]:
        """Search audit events with filters, pagination, and sorting.

        Args:
            actor_id: Filter by actor (user/api key) ID.
            action: Filter by action type.
            severity: Filter by severity level.
            outcome: Filter by outcome.
            resource_type: Filter by resource type.
            resource_id: Filter by resource ID.
            since: Include events after this timestamp (ISO-8601).
            until: Include events before this timestamp (ISO-8601).
            limit: Maximum results (default 50, max 200).
            offset: Results to skip.
            sort_by: Field to sort by (default "timestamp").
            sort_order: "asc" or "desc" (default "desc").

        Returns:
            Tuple of (matching events list, total count).
        """
