"""Inbound port: the Service API contract that driving adapters depend on.

Why a separate port?
    The web adapter (or any future driving adapter — CLI, desktop, tests) must
    depend on an abstract contract, not on concrete use-case classes. This keeps
    the hexagonal dependency arrow clean: driving adapter → driving port ←
    application layer. Swapping the implementation (e.g. adding authentication,
    rate limiting, or audit logging) happens behind this port without touching
    any adapter.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

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


class ServiceAPI(ABC):
    """The operations a driving adapter may invoke on the application core."""

    @abstractmethod
    def create_assessment(
        self, request: CreateAssessmentRequest
    ) -> CreateAssessmentResponse:
        ...

    @abstractmethod
    def start_assessment(
        self, request: StartAssessmentRequest
    ) -> StartAssessmentResponse:
        ...

    @abstractmethod
    def submit_assessment(
        self, request: SubmitAssessmentRequest
    ) -> SubmitAssessmentResponse:
        ...

    @abstractmethod
    def cancel_assessment(
        self, request: CancelAssessmentRequest
    ) -> CancelAssessmentResponse:
        ...

    @abstractmethod
    def list_assessments(
        self, request: ListAssessmentsRequest
    ) -> ListAssessmentsResponse:
        ...

    @abstractmethod
    def get_assessment(self, request: GetAssessmentRequest) -> AssessmentView:
        ...

    @abstractmethod
    def generate_report(
        self, request: GenerateReportRequest
    ) -> GenerateReportResponse:
        ...

    @abstractmethod
    def delete_assessment(
        self, request: DeleteAssessmentRequest
    ) -> DeleteAssessmentResponse:
        ...
