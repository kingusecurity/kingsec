"""Executive Summary Generator — produces a strategic overview for management.

Pure application-layer component. Stateless, deterministic, side-effect free.
Operates only on already-computed pipeline data.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kingsec.application.attack_path import AttackGraph
    from kingsec.application.enrichment import EnrichedFinding
    from kingsec.application.risk import RiskAssessment


# ---------------------------------------------------------------------------
# Value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExecutiveSummary:
    """Strategic executive summary for management stakeholders.

    Captures the security posture, risk statistics, top concerns,
    observations, and recommended actions — all determined purely
    from the pipeline outputs. No AI, no LLMs, no randomness.
    """

    overall_security_posture: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    informational_count: int
    overall_risk_level: str
    highest_risk_score: int
    average_risk_score: float
    total_affected_assets: int
    attack_path_count: int
    highest_attack_path_score: int
    top_security_concerns: tuple[str, ...]
    key_observations: tuple[str, ...]
    executive_recommendations: tuple[str, ...]
    prioritized_remediation_items: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.total_findings < 0:
            raise ValueError("total_findings must not be negative")
        if not 0 <= self.highest_risk_score <= 100:
            raise ValueError("highest_risk_score must be between 0 and 100")
        if not 0.0 <= self.average_risk_score <= 100.0:
            raise ValueError("average_risk_score must be between 0 and 100")
        if self.attack_path_count < 0:
            raise ValueError("attack_path_count must not be negative")
        if not 0 <= self.highest_attack_path_score <= 100:
            raise ValueError("highest_attack_path_score must be between 0 and 100")

    @property
    def total_severe(self) -> int:
        """Critical + High count."""
        return self.critical_count + self.high_count


# ---------------------------------------------------------------------------
# Posture & level helpers (deterministic)
# ---------------------------------------------------------------------------

_POSTURE_MAP: dict[int, str] = {
    4: "Critical",
    3: "Poor",
    2: "Fair",
    1: "Good",
    0: "Excellent",
}

_LEVEL_MAP: dict[int, str] = {
    4: "Critical",
    3: "High",
    2: "Medium",
    1: "Low",
    0: "Informational",
}


def _highest_severity_present(
    critical: int, high: int, medium: int, low: int, informational: int,
) -> int:
    if critical > 0:
        return 4
    if high > 0:
        return 3
    if medium > 0:
        return 2
    if low > 0:
        return 1
    return 0


def _determine_posture(
    posture_level: int, attack_path_count: int, highest_path_score: int,
) -> str:
    base = _POSTURE_MAP.get(posture_level, "Excellent")
    if attack_path_count >= 5 and base not in ("Critical",):
        return "Poor"
    if highest_path_score >= 80 and base not in ("Critical", "Poor"):
        return "Poor" if base == "Fair" else base
    return base


# ---------------------------------------------------------------------------
# Concern / observation / recommendation helpers (deterministic)
# ---------------------------------------------------------------------------


def _build_top_concerns(
    critical: int, high: int, medium: int, low: int, informational: int,
    attack_path_count: int, highest_path_score: int,
    total_assets: int,
) -> tuple[str, ...]:
    concerns: list[str] = []
    if critical > 0:
        concerns.append(
            f"{critical} critical severity finding(s) require immediate attention"
        )
    if high > 0:
        concerns.append(f"{high} high-risk finding(s) present in the environment")
    if medium > 0:
        concerns.append(f"{medium} medium-risk finding(s) should be reviewed")
    if attack_path_count > 0 and highest_path_score >= 60:
        concerns.append(
            f"{attack_path_count} attack path(s) identified with "
            f"maximum score {highest_path_score}"
        )
    if not concerns:
        concerns.append("No significant security concerns detected")
    return tuple(concerns)


def _build_observations(
    total_findings: int, critical: int, high: int,
    total_assets: int, attack_path_count: int,
    enriched_findings: list[EnrichedFinding],
) -> tuple[str, ...]:
    obs: list[str] = []
    if total_findings == 0:
        obs.append("No findings were discovered during the scan")
        return tuple(obs)
    scanner_sources: set[str] = set()
    for f in enriched_findings:
        scanner_sources.update(f.scanner_sources)
    scanner_count = len(scanner_sources)
    obs.append(
        f"Scan covered {total_assets} asset(s) using "
        f"{scanner_count} scanner(s)"
    )
    severe = critical + high
    if severe > 0:
        ratio = round(severe / total_findings * 100)
        obs.append(
            f"{severe} of {total_findings} finding(s) ({ratio}%) "
            f"are high or critical severity"
        )
    if attack_path_count > 0:
        obs.append(
            f"{attack_path_count} attack chain(s) identified, "
            f"indicating potential lateral movement paths"
        )
    categories: Counter[str] = Counter()
    for f in enriched_findings:
        categories[f.category] += 1
    top_cat = categories.most_common(1)
    if top_cat:
        obs.append(f"Most common category: {top_cat[0][0]} ({top_cat[0][1]} finding(s))")
    return tuple(obs)


def _build_recommendations(
    critical: int, high: int, medium: int,
    attack_path_count: int, highest_path_score: int,
    total_assets: int,
) -> tuple[str, ...]:
    recs: list[str] = []
    if critical > 0:
        recs.append("Address all critical-severity findings immediately")
    if high > 0:
        recs.append("Prioritize remediation of high-risk vulnerabilities")
    if medium > 0:
        recs.append("Schedule medium-risk findings for next maintenance window")
    if attack_path_count > 0 and highest_path_score >= 60:
        recs.append("Review and disrupt identified attack paths")
    if total_assets > 0:
        recs.append("Maintain comprehensive asset inventory and scanning coverage")
    recs.append("Establish continuous security monitoring and regular scanning")
    return tuple(recs)


def _build_remediation_items(
    enriched_findings: list[EnrichedFinding],
    risk_assessments: list[RiskAssessment],
) -> tuple[str, ...]:
    risk_map = {a.correlation_id: a for a in risk_assessments}

    scored: list[tuple[int, str]] = []
    for f in enriched_findings:
        ra = risk_map.get(f.correlation_id)
        score = ra.score if ra else 0
        for rec in f.recommendations:
            scored.append((-score, rec))

    scored.sort()
    items = [rec for _, rec in scored]
    return tuple(items)


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class ExecutiveSummaryGenerator:
    """Stateless generator of executive summaries.

    Deterministic, side-effect free. No AI, no randomness, no networking.
    """

    def generate(
        self,
        risk_assessments: list[RiskAssessment],
        attack_graph: AttackGraph,
        enriched_findings: list[EnrichedFinding],
    ) -> ExecutiveSummary:
        """Generate a complete ExecutiveSummary from pipeline outputs."""
        severity_counts: Counter[str] = Counter()
        for ra in risk_assessments:
            severity_counts[ra.risk_level] += 1

        critical = severity_counts.get("Critical", 0)
        high = severity_counts.get("High", 0)
        medium = severity_counts.get("Medium", 0)
        low = severity_counts.get("Low", 0)
        informational = severity_counts.get("Informational", 0)

        total_findings = len(enriched_findings)

        scores = [ra.score for ra in risk_assessments]
        highest_score = max(scores) if scores else 0
        avg_score = sum(scores) / len(scores) if scores else 0.0

        all_assets: set[str] = set()
        for f in enriched_findings:
            all_assets.update(f.affected_assets)
        total_assets = len(all_assets)

        attack_path_count = attack_graph.total_paths
        highest_path_score = attack_graph.highest_score

        level = _highest_severity_present(critical, high, medium, low, informational)
        overall_risk_level = _LEVEL_MAP.get(level, "Informational")

        overall_posture = _determine_posture(level, attack_path_count, highest_path_score)

        concerns = _build_top_concerns(
            critical, high, medium, low, informational,
            attack_path_count, highest_path_score, total_assets,
        )
        observations = _build_observations(
            total_findings, critical, high,
            total_assets, attack_path_count, enriched_findings,
        )
        recommendations = _build_recommendations(
            critical, high, medium,
            attack_path_count, highest_path_score, total_assets,
        )
        remediation_items = _build_remediation_items(
            enriched_findings, risk_assessments,
        )

        return ExecutiveSummary(
            overall_security_posture=overall_posture,
            total_findings=total_findings,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            informational_count=informational,
            overall_risk_level=overall_risk_level,
            highest_risk_score=highest_score,
            average_risk_score=round(avg_score, 2),
            total_affected_assets=total_assets,
            attack_path_count=attack_path_count,
            highest_attack_path_score=highest_path_score,
            top_security_concerns=concerns,
            key_observations=observations,
            executive_recommendations=recommendations,
            prioritized_remediation_items=remediation_items,
        )
