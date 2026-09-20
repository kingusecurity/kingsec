"""Session-bound SQLAlchemy repository implementations.

Re-exports the legacy autocommit repositories from ``_legacy_repositories``
alongside new session-bound implementations.
"""

from __future__ import annotations

from kingsec.infrastructure.persistence._legacy_repositories import (
    LegacyAssessmentRepository,
    LegacyAuthorizationGrantRepository,
    LegacyReportRepository,
)

from .assessment import SQLAlchemyAssessmentRepository
from .asset import SQLAlchemyAssetRepository
from .authorization_grant import SQLAlchemyAuthorizationGrantRepository
from .job import SQLAlchemyJobRepository
from .report import SQLAlchemyReportRepository
from .scan import SQLAlchemyScanRepository

__all__ = [
    "LegacyAssessmentRepository",
    "LegacyAuthorizationGrantRepository",
    "LegacyReportRepository",
    "SQLAlchemyAssessmentRepository",
    "SQLAlchemyAssetRepository",
    "SQLAlchemyAuthorizationGrantRepository",
    "SQLAlchemyJobRepository",
    "SQLAlchemyReportRepository",
    "SQLAlchemyScanRepository",
]
