"""Concrete ServiceAPI implementation — thin facade over the four use cases.

This lives in the application layer because it depends only on other
application-layer types (use cases, DTOs, the ServiceAPI port). It contains
zero business logic — pure delegation — so it does not need tests beyond
verifying the wiring is correct (covered by the integration tests).
"""

from __future__ import annotations

from kingsec.application.dto import (
    AssessmentView,
    CreateAssessmentRequest,
    CreateAssessmentResponse,
    GenerateReportRequest,
    GenerateReportResponse,
    GetAssessmentRequest,
    StartAssessmentRequest,
    StartAssessmentResponse,
)
from kingsec.application.ports.inbound.service_api import ServiceAPI
from kingsec.application.use_cases.create_assessment import CreateAssessment
from kingsec.application.use_cases.generate_report import GenerateReport
from kingsec.application.use_cases.get_assessment import GetAssessment
from kingsec.application.use_cases.start_assessment import StartAssessment


class UseCaseServiceAPI(ServiceAPI):
    """Delegates each operation to the corresponding use case."""

    def __init__(
        self,
        create_assessment: CreateAssessment,
        start_assessment: StartAssessment,
        get_assessment: GetAssessment,
        generate_report: GenerateReport,
    ) -> None:
        self._create = create_assessment
        self._start = start_assessment
        self._get = get_assessment
        self._generate = generate_report

    def create_assessment(
        self, request: CreateAssessmentRequest
    ) -> CreateAssessmentResponse:
        return self._create.execute(request)

    def start_assessment(
        self, request: StartAssessmentRequest
    ) -> StartAssessmentResponse:
        return self._start.execute(request)

    def get_assessment(self, request: GetAssessmentRequest) -> AssessmentView:
        return self._get.execute(request)

    def generate_report(
        self, request: GenerateReportRequest
    ) -> GenerateReportResponse:
        return self._generate.execute(request)
