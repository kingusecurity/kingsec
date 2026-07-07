"""CreateAssessment use case."""

from __future__ import annotations

from kingsec.application import (
    CreateAssessment,
    CreateAssessmentRequest,
    InputValidationError,
)
from kingsec.domain import AssessmentId, AssessmentStatus
import pytest

from tests.unit.application.conftest import InMemoryAssessmentRepository


def _request(**overrides: str) -> CreateAssessmentRequest:
    data = {
        "target_value": "10.0.0.5",
        "target_type": "ip_address",
        "authorized_by": "pentester@kingsec.io",
        "scope": "10.0.0.5",
    }
    data.update(overrides)
    return CreateAssessmentRequest(**data)  # type: ignore[arg-type]


class TestHappyPath:
    def test_creates_authorized_and_persisted_assessment(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        response = CreateAssessment(assessments).execute(_request())

        # Authorization is captured up front, so the assessment is AUTHORIZED.
        assert response.status == AssessmentStatus.AUTHORIZED.value
        # It was actually persisted and is retrievable.
        stored = assessments.get(AssessmentId(response.assessment_id))
        assert stored.is_authorized is True
        assert stored.status is AssessmentStatus.AUTHORIZED


class TestValidation:
    def test_invalid_target_type_raises_input_error(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        with pytest.raises(InputValidationError, match="invalid target type"):
            CreateAssessment(assessments).execute(_request(target_type="banana"))

    def test_empty_target_value_raises_input_error(
        self, assessments: InMemoryAssessmentRepository
    ) -> None:
        with pytest.raises(InputValidationError):
            CreateAssessment(assessments).execute(_request(target_value="  "))
