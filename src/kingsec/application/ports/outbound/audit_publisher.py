"""Outbound port: audit trail publisher.

The application layer defines *what* gets recorded. The infrastructure decides
*how* it is stored (SQLite, append-only file, external service). This port is
the seam between business logic and audit storage.

The ``record`` method is append-only by contract. Implementations MUST NOT
update or delete existing entries. This is a business invariant, not an
implementation detail.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.audit import AuditEntry


class AuditPublisher(ABC):
    """Publishes immutable audit entries to the audit trail."""

    @abstractmethod
    def record(self, entry: AuditEntry) -> None:
        """Append an audit entry to the trail.

        Args:
            entry: The immutable audit record to persist.

        Raises:
            AuditRecordError: If the entry cannot be recorded.
        """
        ...
