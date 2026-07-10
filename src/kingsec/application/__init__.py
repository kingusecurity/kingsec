"""Application layer: use cases plus the port contracts the core owns."""

from .dto import (
    AssessmentView,
    CreateAssessmentRequest,
    CreateAssessmentResponse,
    FindingView,
    GenerateReportRequest,
    GenerateReportResponse,
    GetAssessmentRequest,
    RenderedReport,
    SeverityCount,
    StartAssessmentRequest,
    StartAssessmentResponse,
)
from .errors import (
    ApplicationError,
    AssessmentNotFoundError,
    InputValidationError,
    ReportNotFoundError,
)
from .ports import (
    AIPort,
    AssessmentRepository,
    ReportGeneratorPort,
    ReportRepository,
    ScannerPort,
    ServiceAPI,
    UnitOfWork,
    UnitOfWorkFactory,
)
from .service_api import UseCaseServiceAPI
from .use_cases.create_assessment import CreateAssessment
from .use_cases.generate_report import GenerateReport
from .use_cases.get_assessment import GetAssessment
from .use_cases.start_assessment import StartAssessment

__all__ = [
    "AIPort",
    "ApplicationError",
    "AssessmentNotFoundError",
    "AssessmentRepository",
    "AssessmentView",
    "CreateAssessment",
    "CreateAssessmentRequest",
    "CreateAssessmentResponse",
    "FindingView",
    "GenerateReport",
    "GenerateReportRequest",
    "GenerateReportResponse",
    "GetAssessment",
    "GetAssessmentRequest",
    "InputValidationError",
    "RenderedReport",
    "ReportGeneratorPort",
    "ReportNotFoundError",
    "ReportRepository",
    "ScannerPort",
    "ServiceAPI",
    "SeverityCount",
    "StartAssessment",
    "StartAssessmentRequest",
    "StartAssessmentResponse",
    "UnitOfWork",
    "UnitOfWorkFactory",
    "UseCaseServiceAPI",
]
