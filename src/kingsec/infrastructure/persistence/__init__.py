"""KingSec SQLite persistence adapter (infrastructure layer).

Implements the application's repository ports using SQLAlchemy 2.x + SQLite,
following the Data Mapper pattern (ORM models kept separate from the pure domain).

Public API
    Engine/session:  create_database_engine, create_session_factory, create_schema,
                     validate_schema_version
    Repositories:    SqlAlchemyAssessmentRepository, SqlAlchemyReportRepository,
                    SqlAlchemyAuditRepository
    ORM base:        Base
    DI wiring:       register_persistence
"""

from __future__ import annotations

from .audit_repository import SqlAlchemyAuditRepository
from .database import (
    build_sqlite_url,
    create_database_engine,
    create_schema,
    create_session_factory,
    validate_schema_version,
)
from .base import Base
from .models import (
    AssetModel,
    AssessmentORM,
    AuditEntryORM,
    EvidenceORM,
    FindingModel,
    FindingORM,
    JobModel,
    RecommendationORM,
    ReportModel,
    ReportORM,
    ScanModel,
    UserORM,
)
from .provisioning import register_persistence
from .repositories import (
    SQLAlchemyAssessmentRepository,
    SqlAlchemyAssessmentRepository,
    SqlAlchemyReportRepository,
)
from .unit_of_work import SqlAlchemyUnitOfWork, SqlAlchemyUnitOfWorkFactory, register_unit_of_work

__all__ = [
    "AssetModel",
    "AssessmentORM",
    "AuditEntryORM",
    "Base",
    "EvidenceORM",
    "FindingModel",
    "FindingORM",
    "JobModel",
    "RecommendationORM",
    "ReportModel",
    "ReportORM",
    "ScanModel",
    "SQLAlchemyAssessmentRepository",
    "SqlAlchemyAssessmentRepository",
    "SqlAlchemyAuditRepository",
    "SqlAlchemyReportRepository",
    "SqlAlchemyUnitOfWork",
    "SqlAlchemyUnitOfWorkFactory",
    "UserORM",
    "build_sqlite_url",
    "create_database_engine",
    "create_schema",
    "create_session_factory",
    "register_persistence",
    "register_unit_of_work",
    "validate_schema_version",
]
