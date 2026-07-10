"""Port definitions - the boundaries between the core and the outside."""

from .inbound import ServiceAPI
from .repositories import AssessmentRepository, ReportRepository
from .services import AIPort, ReportGeneratorPort, ScannerPort
from .unit_of_work import UnitOfWork, UnitOfWorkFactory

__all__ = [
    "AIPort",
    "AssessmentRepository",
    "ReportGeneratorPort",
    "ReportRepository",
    "ScannerPort",
    "ServiceAPI",
    "UnitOfWork",
    "UnitOfWorkFactory",
]
