"""Attack Path Analysis Engine: comprehensive tests."""

from __future__ import annotations

import pytest

from kingsec.application.attack_path import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    AttackPath,
    AttackPathAnalyzer,
)
from kingsec.application.enrichment import EnrichedFinding
from kingsec.application.risk import RiskAssessment, RiskFactor
from kingsec.domain import Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ENGINE = AttackPathAnalyzer()


def _make_factor(
    name: str = "severity",
    weight: int = 30,
    contribution: int = 22,
    description: str = "Severity is HIGH",
) -> RiskFactor:
    return RiskFactor(name=name, weight=weight,
                      contribution=contribution, description=description)


def _make_assessment(
    correlation_id: str = "corr-001",
    score: int = 60,
    risk_level: str = "High",
    priority: str = "High",
    factors: tuple[RiskFactor, ...] | None = None,
) -> RiskAssessment:
    if factors is None:
        factors = (
            _make_factor(name="severity", description="Severity is HIGH"),
            _make_factor(name="confidence", weight=15, contribution=9,
                         description="Confidence is 0.60"),
            _make_factor(name="exploit_likelihood", weight=15, contribution=10,
                         description="Exploit likelihood is Medium"),
            _make_factor(name="business_impact", weight=15, contribution=7,
                         description="Business impact is Medium"),
            _make_factor(name="attack_surface", weight=10, contribution=8,
                         description="Attack surface is Network Service"),
            _make_factor(name="scanner_count", weight=10, contribution=6,
                         description="Detected by 2 scanner(s)"),
            _make_factor(name="risk_factors", weight=5, contribution=3,
                         description="2 risk factor(s) identified"),
        )
    return RiskAssessment(
        correlation_id=correlation_id,
        score=score,
        risk_level=risk_level,
        priority=priority,
        reasoning=f"Risk score {score}/100 ({risk_level}).",
        factors=factors,
    )


def _make_finding(
    correlation_id: str = "corr-001",
    title: str = "SSH Vulnerability",
    description: str = "OpenSSH issue on host 10.0.0.1",
    severity: Severity = Severity.HIGH,
    category: str = "vulnerability",
    affected_assets: tuple[str, ...] = ("10.0.0.1",),
    service: str | None = "SSH",
    protocol: str | None = "TCP",
    port: int | None = 22,
    attack_surface: str | None = "Network Service",
    software: tuple[str, ...] = ("openssh", "ssh"),
    business_impact: str | None = "Medium",
    exploit_likelihood: str | None = "Medium",
    remediation_complexity: str | None = "Medium",
    confidence: float = 0.60,
    scanner_sources: tuple[str, ...] = ("nuclei",),
    recommendations: tuple[str, ...] = (),
    risk_factors: tuple[str, ...] = ("Remote Code Execution",),
    tags: tuple[str, ...] = (),
) -> EnrichedFinding:
    return EnrichedFinding(
        correlation_id=correlation_id,
        title=title,
        description=description,
        severity=severity,
        category=category,
        confidence=confidence,
        scanner_sources=scanner_sources,
        affected_assets=affected_assets,
        references=(),
        recommendations=recommendations,
        tags=tags,
        software=software,
        service=service,
        protocol=protocol,
        port=port,
        technology=(),
        operating_system=None,
        attack_surface=attack_surface,
        risk_factors=risk_factors,
        business_impact=business_impact,
        exploit_likelihood=exploit_likelihood,
        remediation_complexity=remediation_complexity,
        priority="Medium",
        metadata={},
    )
