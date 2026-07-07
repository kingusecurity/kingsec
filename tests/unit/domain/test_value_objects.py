"""Value objects: immutability, value-equality, and validation."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest

from kingsec.domain import (
    AssessmentId,
    Authorization,
    Evidence,
    FindingId,
    InvariantViolation,
    Recommendation,
    Severity,
    Target,
    TargetType,
)
from tests.unit.domain.conftest import utc


class TestIdentifiers:
    def test_generated_ids_are_unique_and_prefixed(self) -> None:
        a, b = AssessmentId.generate(), AssessmentId.generate()
        assert a != b
        assert a.value.startswith("asmt-")
        assert FindingId.generate().value.startswith("find-")

    def test_value_equality(self) -> None:
        assert AssessmentId("x") == AssessmentId("x")
        assert AssessmentId("x") != AssessmentId("y")

    def test_empty_id_is_rejected(self) -> None:
        with pytest.raises(InvariantViolation):
            AssessmentId("   ")

    def test_id_is_immutable(self) -> None:
        with pytest.raises(dataclasses.FrozenInstanceError):
            AssessmentId("x").value = "y"  # type: ignore[misc]


class TestTarget:
    def test_requires_non_empty_value(self) -> None:
        with pytest.raises(InvariantViolation):
            Target("", TargetType.URL)

    def test_requires_target_type(self) -> None:
        with pytest.raises(InvariantViolation):
            Target("host", "url")  # type: ignore[arg-type]


class TestAuthorization:
    def test_valid_authorization(self) -> None:
        auth = Authorization("alice", utc(), scope="10.0.0.0/24")
        assert auth.authorized_by == "alice"

    def test_naive_datetime_is_rejected(self) -> None:
        naive = datetime(2026, 1, 1)  # no tzinfo
        with pytest.raises(InvariantViolation):
            Authorization("alice", naive, scope="x")

    def test_missing_scope_is_rejected(self) -> None:
        with pytest.raises(InvariantViolation):
            Authorization("alice", utc(), scope=" ")


class TestEvidence:
    def test_requires_timezone_aware_timestamp(self) -> None:
        with pytest.raises(InvariantViolation):
            Evidence("summary", "detail", datetime(2026, 1, 1))

    def test_requires_non_empty_fields(self) -> None:
        with pytest.raises(InvariantViolation):
            Evidence("", "detail", utc())

    def test_create_stamps_utc(self) -> None:
        ev = Evidence.create("summary", "detail")
        assert ev.collected_at.tzinfo is timezone.utc
        assert ev.collected_at.tzinfo is not None


class TestRecommendation:
    def test_valid(self) -> None:
        rec = Recommendation("Patch", "Upgrade to 2.1", Severity.HIGH)
        assert rec.priority is Severity.HIGH

    def test_requires_severity_priority(self) -> None:
        with pytest.raises(InvariantViolation):
            Recommendation("Patch", "desc", "high")  # type: ignore[arg-type]


class TestSeverityOrdering:
    def test_is_ordered(self) -> None:
        assert Severity.CRITICAL > Severity.HIGH > Severity.LOW > Severity.INFORMATIONAL

    def test_max_selects_worst(self) -> None:
        assert max([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL

    def test_label(self) -> None:
        assert Severity.CRITICAL.label == "Critical"
