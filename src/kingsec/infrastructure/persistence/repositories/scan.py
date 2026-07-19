"""Session-bound SQLAlchemy Scan repository.

Persists and retrieves :class:`ScannerResult` objects through the existing
``ScanModel`` / ``FindingModel`` ORM models.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from kingsec.application import AssessmentNotFoundError, ScanRepositoryPort
from kingsec.domain import ScannerResult
from kingsec.infrastructure.persistence.mappers import (
    scan_result_to_domain,
    scan_result_to_orm,
)
from kingsec.infrastructure.persistence.models import ScanModel


class SQLAlchemyScanRepository(ScanRepositoryPort):
    """Implements :class:`ScanRepositoryPort` on a caller-owned session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, scan_id: str, result: ScannerResult) -> None:
        existing = self._session.get(ScanModel, scan_id)
        if existing is not None:
            self._session.delete(existing)
            self._session.flush()
        self._session.add(scan_result_to_orm(scan_id, result))

    def get(self, scan_id: str) -> ScannerResult:
        orm = self._session.get(ScanModel, scan_id)
        if orm is None:
            raise AssessmentNotFoundError(scan_id)
        return scan_result_to_domain(orm)

    def exists(self, scan_id: str) -> bool:
        orm = self._session.get(ScanModel, scan_id)
        return orm is not None

    def delete(self, scan_id: str) -> None:
        orm = self._session.get(ScanModel, scan_id)
        if orm is None:
            raise AssessmentNotFoundError(scan_id)
        self._session.delete(orm)
