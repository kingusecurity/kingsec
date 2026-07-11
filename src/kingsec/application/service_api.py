"""Concrete ServiceAPI implementation — thin facade over use cases.

This lives in the application layer because it depends only on other
application-layer types (use cases, DTOs, the ServiceAPI port). It contains
zero business logic — pure delegation — so it does not need tests beyond
verifying the wiring is correct (covered by the integration tests).
"""

from __future__ import annotations

from kingsec.application.dto import (
    AssessmentView,
    CancelAssessmentRequest,
    CancelAssessmentResponse,
    CreateAssessmentRequest,
    CreateAssessmentResponse,
    DeleteAssessmentRequest,
    DeleteAssessmentResponse,
    GenerateReportRequest,
    GenerateReportResponse,
    GetAssessmentRequest,
    ListAssessmentsRequest,
    ListAssessmentsResponse,
    StartAssessmentRequest,
    StartAssessmentResponse,
    SubmitAssessmentRequest,
    SubmitAssessmentResponse,
)
from kingsec.application.ports.inbound.service_api import ServiceAPI
from kingsec.application.submit_assessment import SubmitAssessment
from kingsec.application.use_cases.cancel_assessment import CancelAssessment
from kingsec.application.use_cases.create_assessment import CreateAssessment
from kingsec.application.use_cases.delete_assessment import DeleteAssessment
from kingsec.application.use_cases.generate_report import GenerateReport
from kingsec.application.use_cases.get_assessment import GetAssessment
from kingsec.application.use_cases.list_assessments import ListAssessments
from kingsec.application.use_cases.start_assessment import StartAssessment


class UseCaseServiceAPI(ServiceAPI):
    """Delegates each operation to the corresponding use case."""

    def __init__(
        self,
        create_assessment: CreateAssessment,
        start_assessment: StartAssessment,
        submit_assessment: SubmitAssessment,
        cancel_assessment: CancelAssessment,
        list_assessments: ListAssessments,
        get_assessment: GetAssessment,
        generate_report: GenerateReport,
        delete_assessment: DeleteAssessment,
    ) -> None:
        self._create = create_assessment
        self._start = start_assessment
        self._submit = submit_assessment
        self._cancel = cancel_assessment
        self._list = list_assessments
        self._get = get_assessment
        self._generate = generate_report
        self._delete = delete_assessment

    def create_assessment(
        self, request: CreateAssessmentRequest
    ) -> CreateAssessmentResponse:
        return self._create.execute(request)

    def start_assessment(
        self, request: StartAssessmentRequest
    ) -> StartAssessmentResponse:
        return self._start.execute(request)

    def submit_assessment(
        self, request: SubmitAssessmentRequest
    ) -> SubmitAssessmentResponse:
        return self._submit.execute(request)

    def cancel_assessment(
        self, request: CancelAssessmentRequest
    ) -> CancelAssessmentResponse:
        return self._cancel.execute(request)

    def list_assessments(
        self, request: ListAssessmentsRequest
    ) -> ListAssessmentsResponse:
        return self._list.execute(request)

    def get_assessment(self, request: GetAssessmentRequest) -> AssessmentView:
        return self._get.execute(request)

    def generate_report(
        self, request: GenerateReportRequest
    ) -> GenerateReportResponse:
        return self._generate.execute(request)

    def delete_assessment(
        self, request: DeleteAssessmentRequest
    ) -> DeleteAssessmentResponse:
        return self._delete.execute(request)
