"""KingSec application layer — use cases and ports.

Depends only on the domain layer and the standard library. Defines the abstract
ports that infrastructure implements, the DTOs that cross the boundary, and the
use cases that orchestrate the domain.

Public API
    Use cases:   CreateAssessment, StartAssessment, GetAssessment, GenerateReport
    Ports:       AssessmentRepository, ReportRepository,
                 ScannerPort, AIPort, ReportGeneratorPort
    DTOs:        *Request / *Response / *View / RenderedReport / SeverityCount
    Errors:      ApplicationError, InputValidationError,
                 AssessmentNotFoundError, ReportNotFoundError
"""

from __future__ import annotations

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
)
from .use_cases import (
    CreateAssessment,
    GenerateReport,
    GetAssessment,
    StartAssessment,
)

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
    "SeverityCount",
    "StartAssessment",
    "StartAssessmentRequest",
    "StartAssessmentResponse",
]
