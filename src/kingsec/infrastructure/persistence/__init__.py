"""KingSec SQLite persistence adapter (infrastructure layer).

Implements the application's repository ports using SQLAlchemy 2.x + SQLite,
following the Data Mapper pattern (ORM models kept separate from the pure domain).

Public API
    Engine/session:  create_database_engine, create_session_factory, create_schema
    Repositories:    SqlAlchemyAssessmentRepository, SqlAlchemyReportRepository
    ORM base:        Base
    DI wiring:       register_persistence
"""

from __future__ import annotations

from .database import (
    build_sqlite_url,
    create_database_engine,
    create_schema,
    create_session_factory,
)
from .models import Base
from .provisioning import register_persistence
from .repositories import (
    SqlAlchemyAssessmentRepository,
    SqlAlchemyReportRepository,
)

__all__ = [
    "Base",
    "SqlAlchemyAssessmentRepository",
    "SqlAlchemyReportRepository",
    "build_sqlite_url",
    "create_database_engine",
    "create_schema",
    "create_session_factory",
    "register_persistence",
]
