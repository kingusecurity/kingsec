"""Session-bound SQLAlchemy repository implementations.

Re-exports the legacy autocommit repositories from ``_legacy_repositories``
alongside new session-bound implementations.
"""

from __future__ import annotations

from kingsec.infrastructure.persistence._legacy_repositories import (
    SqlAlchemyAssessmentRepository as _LegacyAssessmentRepo,
    SqlAlchemyReportRepository as _LegacyReportRepo,
)

# Legacy autocommit repositories (session-per-call, own their transaction).
SqlAlchemyAssessmentRepository = _LegacyAssessmentRepo
SqlAlchemyReportRepository = _LegacyReportRepo

from .assessment import SQLAlchemyAssessmentRepository  # noqa: E402, F811
from .report import SQLAlchemyReportRepository  # noqa: E402, F811
from .scan import SQLAlchemyScanRepository  # noqa: E402, F811

__all__ = [
    "SQLAlchemyAssessmentRepository",
    "SQLAlchemyReportRepository",
    "SQLAlchemyScanRepository",
    "SqlAlchemyAssessmentRepository",
    "SqlAlchemyReportRepository",
]
