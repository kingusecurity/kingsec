"""Shared fixtures/builders for reporting tests."""

from __future__ import annotations

import io
from datetime import UTC, datetime

from kingsec.domain import (
    Assessment,
    Authorization,
    Evidence,
    Finding,
    Recommendation,
    Report,
    ScannerRunSummary,
    Severity,
    Target,
    TargetType,
)
from kingsec.infrastructure.config.models import LoggingSettings
from kingsec.infrastructure.logging import configure_logging

configure_logging(LoggingSettings(level="ERROR", json_format=True), stream=io.StringIO())

_FIXED = datetime(2026, 7, 7, 12, 0, 0, tzinfo=UTC)


def build_report(
    *,
    title: str = "SQL Injection",
    with_findings: bool = True,
    scanner_summary: tuple[ScannerRunSummary, ...] = (),
) -> Report:
    """Build a Report snapshot from a completed assessment."""
    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization("tester", _FIXED, scope="10.0.0.5"))
    assessment.start()
    if with_findings:
        critical = Finding.create(title, "injectable parameter", Severity.CRITICAL)
        critical.add_evidence(Evidence("m", "matched-at http://10.0.0.5", _FIXED))
        critical.add_recommendation(Recommendation("Fix", "use params", Severity.CRITICAL))
        critical.confirm()
        assessment.record_finding(critical)
        assessment.record_finding(Finding.create("Missing headers", "no CSP", Severity.LOW))
    if scanner_summary:
        assessment.record_scanner_summary(scanner_summary)
    assessment.complete()
    return Report.from_assessment(assessment, generated_at=_FIXED)
