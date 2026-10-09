"""Value objects: immutability, value-equality, and validation."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest
from tests.unit.domain.conftest import utc

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

    @pytest.mark.parametrize("value", ["example.com", "security.example.pk"])
    def test_accepts_domain_enumeration_targets(self, value: str) -> None:
        assert Target(value, TargetType.DOMAIN).value == value

    @pytest.mark.parametrize(
        "value", ["localhost", "example.test", "home.arpa", "example.alt", "example.123", "example.com."]
    )
    def test_rejects_non_public_domain_enumeration_targets(self, value: str) -> None:
        with pytest.raises(InvariantViolation):
            Target(value, TargetType.DOMAIN)

    @pytest.mark.parametrize("value", ["/srv/customer/source", r"C:\customer\source"])
    def test_accepts_absolute_source_paths_for_linux_and_windows(self, value: str) -> None:
        assert Target(value, TargetType.SOURCE_PATH).value == value

    @pytest.mark.parametrize(
        "value",
        [
            "relative/source",
            r"\root-relative",
            r"\\server\share\source",
            "//server/share/source",
            "/srv/customer/../secret",
            "C:\\source\nother",
        ],
    )
    def test_rejects_ambiguous_source_paths(self, value: str) -> None:
        with pytest.raises(InvariantViolation):
            Target(value, TargetType.SOURCE_PATH)

    @pytest.mark.parametrize(
        "value",
        [
            "alpine:3.20",
            "ghcr.io/example/application:v1.2.3",
            "registry.example.com:5000/team/application@sha256:" + "a" * 64,
        ],
    )
    def test_accepts_container_image_references(self, value: str) -> None:
        assert Target(value, TargetType.CONTAINER_IMAGE).value == value

    @pytest.mark.parametrize(
        "value",
        ["https://registry.example.com/image", "-malicious", "Uppercase/Repository:tag", "registry:70000/app"],
    )
    def test_rejects_invalid_container_image_references(self, value: str) -> None:
        with pytest.raises(InvariantViolation):
            Target(value, TargetType.CONTAINER_IMAGE)


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
        assert ev.collected_at.tzinfo is UTC
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
