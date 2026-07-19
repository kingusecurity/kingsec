"""Session-bound SQLAlchemy repository implementations.

Re-exports the legacy autocommit repositories from ``_legacy_repositories``
alongside new session-bound implementations.
"""

from __future__ import annotations

from kingsec.infrastructure.persistence._legacy_repositories import (
    SqlAlchemyAssessmentRepository as _LegacyAssessmentRepo,
)
from kingsec.infrastructure.persistence._legacy_repositories import (
    SqlAlchemyReportRepository as _LegacyReportRepo,
)

# Legacy autocommit repositories (session-per-call, own their transaction).
SqlAlchemyAssessmentRepository = _LegacyAssessmentRepo
SqlAlchemyReportRepository = _LegacyReportRepo

from .assessment import SQLAlchemyAssessmentRepository
from .asset import SQLAlchemyAssetRepository
from .job import SQLAlchemyJobRepository
from .report import SQLAlchemyReportRepository
from .scan import SQLAlchemyScanRepository

__all__ = [
    "SQLAlchemyAssessmentRepository",
    "SQLAlchemyAssetRepository",
    "SQLAlchemyJobRepository",
    "SQLAlchemyReportRepository",
    "SQLAlchemyScanRepository",
    "SqlAlchemyAssessmentRepository",
    "SqlAlchemyReportRepository",
]
