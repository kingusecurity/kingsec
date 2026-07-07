"""Builders shared by persistence unit tests."""

from __future__ import annotations

from datetime import datetime, timezone

from kingsec.domain import (
    Assessment,
    Authorization,
    Evidence,
    Finding,
    Recommendation,
    Severity,
    Target,
    TargetType,
)


def utc(day: int = 1) -> datetime:
    return datetime(2026, 1, day, tzinfo=timezone.utc)


def completed_assessment() -> Assessment:
    """A COMPLETED assessment with one enriched, confirmed finding."""

    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization("tester", utc(), scope="10.0.0.5"))
    assessment.start()

    finding = Finding.create("SQL Injection", "id param injectable", Severity.CRITICAL)
    finding.add_evidence(Evidence("payload", "' OR 1=1--", utc(2)))
    finding.add_recommendation(
        Recommendation("Parameterize queries", "Use bound params", Severity.CRITICAL)
    )
    finding.confirm()
    assessment.record_finding(finding)

    low = Finding.create("Missing headers", "no CSP", Severity.LOW)
    assessment.record_finding(low)

    assessment.complete()
    return assessment
