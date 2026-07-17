"""Risk Scoring Engine.

Offline, deterministic risk scoring for enriched findings. Uses only the
information already present in ``EnrichedFinding`` to produce a numeric
risk score (0–100), a risk level, priority, reasoning, and a breakdown
of contributing factors.

Design principles:
    * Immutable value objects (frozen dataclasses).
    * Stateless scorer — pure functions, no side effects.
    * Deterministic and stable output.
    * No infrastructure, plugin, or scanner imports.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from kingsec.domain import Severity

if TYPE_CHECKING:
    from kingsec.application.enrichment import EnrichedFinding


# ---------------------------------------------------------------------------
# Weight tables (heuristic, offline, deterministic)
# ---------------------------------------------------------------------------

_SEVERITY_CONTRIBUTION: dict[Severity, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 22,
    Severity.MEDIUM: 14,
    Severity.LOW: 6,
    Severity.INFORMATIONAL: 0,
}

_EXPLOIT_LIKELIHOOD_CONTRIBUTION: dict[str, int] = {
    "High": 15,
    "Medium": 10,
    "Low": 5,
}

_BUSINESS_IMPACT_CONTRIBUTION: dict[str, int] = {
    "Critical": 15,
    "High": 11,
    "Medium": 7,
    "Low": 3,
}

_ATTACK_SURFACE_CONTRIBUTION: dict[str, int] = {
    "Web Application": 10,
    "API": 9,
    "Network Service": 8,
    "Database": 8,
    "Cloud": 7,
    "Authentication": 7,
    "Container": 6,
    "File System": 6,
    "Network Infrastructure": 5,
    "DNS": 4,
}

_SCANNER_COUNT_CONTRIBUTION: list[tuple[int, int]] = [
    (4, 10),
    (3, 8),
    (2, 6),
    (1, 3),
    (0, 0),
]

_RISK_FACTOR_COUNT_CONTRIBUTION: list[tuple[int, int]] = [
    (4, 5),
    (3, 4),
    (2, 3),
    (1, 2),
    (0, 0),
]

_RISK_LEVEL_THRESHOLDS: list[tuple[int, str]] = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (25, "Low"),
]

_PRIORITY_THRESHOLDS: list[tuple[int, str]] = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
]


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RiskFactor:
    """A single contributing factor in a risk assessment.

    Each factor describes one dimension of the risk score, its weight
    (maximum possible contribution), and the actual points contributed.
    """

    name: str
    weight: int
    contribution: int
    description: str


@dataclass(frozen=True)
class RiskAssessment:
    """A comprehensive risk assessment for a single enriched finding.

    Produced by ``RiskScorer.score()``. Contains a numeric score,
    human-readable risk level, priority, explanatory reasoning, and a
    breakdown of all contributing factors.
    """

    correlation_id: str
    score: int
    risk_level: str
    priority: str
    reasoning: str
    factors: tuple[RiskFactor, ...]

    def __post_init__(self) -> None:
        if not self.correlation_id:
            raise ValueError("correlation_id must not be empty")
        if not 0 <= self.score <= 100:
            raise ValueError("score must be between 0 and 100")
        if not self.factors:
            raise ValueError("factors must not be empty")


# ---------------------------------------------------------------------------
# Risk Scorer
# ---------------------------------------------------------------------------


class RiskScorer:
    """Stateless risk scoring engine for enriched findings.

    Every method is deterministic and purely derived from the fields
    already present in ``EnrichedFinding``. No external services.
    """

    def score(self, finding: EnrichedFinding) -> RiskAssessment:
        """Produce a full risk assessment for a single enriched finding.

        Args:
            finding: An enriched finding from the enrichment engine.

        Returns:
            A ``RiskAssessment`` with score, level, priority, reasoning,
            and contributing factors.
        """
        factors: list[RiskFactor] = []

        # 1. Severity
        severity_pts = _SEVERITY_CONTRIBUTION.get(finding.severity, 0)
        factors.append(RiskFactor(
            name="severity",
            weight=30,
            contribution=severity_pts,
            description=f"Severity is {finding.severity.name}",
        ))

        # 2. Confidence
        confidence_pts = int(finding.confidence * 15)
        factors.append(RiskFactor(
            name="confidence",
            weight=15,
            contribution=confidence_pts,
            description=f"Confidence is {finding.confidence:.2f}",
        ))

        # 3. Exploit likelihood
        likelihood_pts = _EXPLOIT_LIKELIHOOD_CONTRIBUTION.get(
            finding.exploit_likelihood, 0
        )
        factors.append(RiskFactor(
            name="exploit_likelihood",
            weight=15,
            contribution=likelihood_pts,
            description=f"Exploit likelihood is {finding.exploit_likelihood or 'unknown'}",
        ))

        # 4. Business impact
        impact_pts = _BUSINESS_IMPACT_CONTRIBUTION.get(
            finding.business_impact, 0
        )
        factors.append(RiskFactor(
            name="business_impact",
            weight=15,
            contribution=impact_pts,
            description=f"Business impact is {finding.business_impact or 'unknown'}",
        ))

        # 5. Attack surface
        surface_pts = _ATTACK_SURFACE_CONTRIBUTION.get(
            finding.attack_surface, 0
        )
        factors.append(RiskFactor(
            name="attack_surface",
            weight=10,
            contribution=surface_pts,
            description=f"Attack surface is {finding.attack_surface or 'unknown'}",
        ))

        # 6. Scanner count
        scanner_count = len(finding.scanner_sources)
        scanner_pts = 0
        for threshold, pts in _SCANNER_COUNT_CONTRIBUTION:
            if scanner_count >= threshold:
                scanner_pts = pts
                break
        factors.append(RiskFactor(
            name="scanner_count",
            weight=10,
            contribution=scanner_pts,
            description=f"Detected by {scanner_count} scanner(s)",
        ))

        # 7. Risk factor count
        risk_count = len(finding.risk_factors)
        risk_pts = 0
        for threshold, pts in _RISK_FACTOR_COUNT_CONTRIBUTION:
            if risk_count >= threshold:
                risk_pts = pts
                break
        factors.append(RiskFactor(
            name="risk_factors",
            weight=5,
            contribution=risk_pts,
            description=f"{risk_count} risk factor(s) identified",
        ))

        factors_tuple = tuple(factors)

        # Total score
        total = sum(f.contribution for f in factors_tuple)
        total = min(total, 100)

        # Risk level
        risk_level = "Informational"
        for threshold, label in _RISK_LEVEL_THRESHOLDS:
            if total >= threshold:
                risk_level = label
                break

        # Priority
        priority = "Low"
        for threshold, label in _PRIORITY_THRESHOLDS:
            if total >= threshold:
                priority = label
                break

        # Reasoning
        reasoning = (
            f"Risk score {total}/100 ({risk_level}). "
            f"Contributing factors: "
            f"severity={severity_pts}, confidence={confidence_pts}, "
            f"exploit_likelihood={likelihood_pts}, "
            f"business_impact={impact_pts}, "
            f"attack_surface={surface_pts}, "
            f"scanner_count={scanner_pts}, "
            f"risk_factors={risk_pts}."
        )

        return RiskAssessment(
            correlation_id=finding.correlation_id,
            score=total,
            risk_level=risk_level,
            priority=priority,
            reasoning=reasoning,
            factors=factors_tuple,
        )
