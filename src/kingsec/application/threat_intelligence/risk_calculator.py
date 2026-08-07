from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from kingsec.domain.threat_intelligence import CveEntry, ExploitMaturity


@dataclass
class ThreatRiskScore:
    business_risk: float = 0.0
    exploitability_score: float = 0.0
    priority_score: float = 0.0
    likelihood: float = 0.0
    overall_threat_score: float = 0.0


class ThreatRiskCalculator:
    BUSINESS_WEIGHT = 0.3
    EXPLOITABILITY_WEIGHT = 0.35
    LIKELIHOOD_WEIGHT = 0.35
    KEV_BOOST = 15.0
    MATURITY_BOOST: ClassVar[dict[ExploitMaturity, float]] = {
        ExploitMaturity.ACTIVE_EXPLOITATION: 20.0,
        ExploitMaturity.WEAPONIZED: 15.0,
        ExploitMaturity.PROOF_OF_CONCEPT: 8.0,
        ExploitMaturity.NO_EXPLOIT: 0.0,
        ExploitMaturity.UNKNOWN: 2.0,
    }

    @classmethod
    def calculate(cls, entry: CveEntry) -> ThreatRiskScore:
        cvss_score = entry.cvss_data.base_score
        epss_score = entry.epss_data.score if entry.epss_data else 0.0
        epss_percentile = entry.epss_data.percentile if entry.epss_data else 0.0

        business_risk = cvss_score
        if entry.is_kev:
            business_risk = min(business_risk + cls.KEV_BOOST, 100.0)

        exploitability_score = entry.cvss_data.exploitability_score
        maturity_boost = cls.MATURITY_BOOST.get(entry.exploit_maturity, 2.0)
        epss_contribution = epss_score * 100 * 0.15
        exploitability_score = min(exploitability_score + maturity_boost + epss_contribution, 100.0)

        likelihood = (epss_percentile * 100 * 0.3) + (maturity_boost * 0.4) + (cvss_score * 0.3)
        likelihood = min(likelihood, 100.0)

        overall = (
            business_risk * cls.BUSINESS_WEIGHT
            + exploitability_score * cls.EXPLOITABILITY_WEIGHT
            + likelihood * cls.LIKELIHOOD_WEIGHT
        )
        overall = min(overall, 100.0)

        return ThreatRiskScore(
            business_risk=round(business_risk, 2),
            exploitability_score=round(exploitability_score, 2),
            priority_score=round(overall, 2),
            likelihood=round(likelihood, 2),
            overall_threat_score=round(overall, 2),
        )

    @classmethod
    def severity_level(cls, score: float) -> str:
        if score >= 75:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        if score >= 10:
            return "low"
        return "none"
