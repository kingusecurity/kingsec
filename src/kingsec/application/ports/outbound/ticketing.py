"""Port for ticketing-system integrations — application layer contract."""

from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.integration import IntegrationType, TicketReference


class TicketingPort(ABC):
    """Abstract port for creating and reading tickets in external ticketing systems."""

    @abstractmethod
    def create_ticket(
        self,
        system: IntegrationType,
        finding_id: str,
        title: str,
        description: str,
        severity: str,
        assessment_target: str,
    ) -> TicketReference | None:
        """Create a ticket in the given system, or return None if skipped/failed."""

    @abstractmethod
    def get_tickets(self, finding_id: str | None = None) -> list[TicketReference]:
        """Return created tickets, optionally filtered to a single finding."""
