"""Risk Scoring Engine: comprehensive tests."""

from __future__ import annotations

import pytest

from kingsec.application.enrichment import EnrichedFinding
from kingsec.application.risk import RiskAssessment, RiskFactor, RiskScorer
from kingsec.domain import Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ENGINE = RiskScorer()


def _make_ef(
    correlation_id: str = "corr-abc",
    title: str = "Test Finding",
    description: str = "A test finding",
    severity: Severity = Severity.HIGH,
    category: str = "vulnerability",
    confidence: float = 0.60,
    scanner_sources: tuple[str, ...] = ("nuclei",),
    affected_assets: tuple[str, ...] = ("10.0.0.1",),
    references: tuple[str, ...] = (),
    recommendations: tuple[str, ...] = (),
    tags: tuple[str, ...] = (),
    software: tuple[str, ...] = (),
    service: str | None = None,
    protocol: str | None = None,
    port: int | None = None,
    technology: tuple[str, ...] = (),
    operating_system: str | None = None,
    attack_surface: str | None = None,
    risk_factors: tuple[str, ...] = (),
    business_impact: str | None = None,
    exploit_likelihood: str | None = None,
    remediation_complexity: str | None = None,
    priority: str = "Low",
    metadata: dict[str, str] | None = None,
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
        references=references,
        recommendations=recommendations,
        tags=tags,
        software=software,
        service=service,
        protocol=protocol,
        port=port,
        technology=technology,
        operating_system=operating_system,
        attack_surface=attack_surface,
        risk_factors=risk_factors,
        business_impact=business_impact,
        exploit_likelihood=exploit_likelihood,
        remediation_complexity=remediation_complexity,
        priority=priority,
        metadata=metadata or {},
    )


# ===========================================================================
# RiskFactor construction
# ===========================================================================


class TestRiskFactor:
    def test_creates_with_valid_data(self) -> None:
        rf = RiskFactor(name="severity", weight=30, contribution=22,
                        description="Severity is HIGH")
        assert rf.name == "severity"
        assert rf.weight == 30
        assert rf.contribution == 22
        assert rf.description == "Severity is HIGH"

    def test_frozen_immutable(self) -> None:
        rf = RiskFactor(name="test", weight=10, contribution=5,
                        description="Test")
        with pytest.raises(AttributeError):
            rf.name = "changed"  # type: ignore[misc]

    def test_zero_contribution(self) -> None:
        rf = RiskFactor(name="test", weight=10, contribution=0,
                        description="No contribution")
        assert rf.contribution == 0


# ===========================================================================
# RiskAssessment construction
# ===========================================================================


class TestRiskAssessmentConstruction:
    def test_creates_with_valid_data(self) -> None:
        factors = (RiskFactor(name="a", weight=10, contribution=5,
                              description="A"),)
        ra = RiskAssessment(
            correlation_id="corr-abc",
            score=55,
            risk_level="Medium",
            priority="Medium",
            reasoning="Score 55/100 (Medium).",
            factors=factors,
        )
        assert ra.correlation_id == "corr-abc"
        assert ra.score == 55
        assert ra.risk_level == "Medium"

    def test_frozen_immutable(self) -> None:
        factors = (RiskFactor(name="a", weight=10, contribution=5,
                              description="A"),)
        ra = RiskAssessment(
            correlation_id="corr-x",
            score=10,
            risk_level="Low",
            priority="Low",
            reasoning="Low risk.",
            factors=factors,
        )
        with pytest.raises(AttributeError):
            ra.score = 99  # type: ignore[misc]

    def test_empty_correlation_id_raises(self) -> None:
        factors = (RiskFactor(name="a", weight=10, contribution=5,
                              description="A"),)
        with pytest.raises(ValueError, match="correlation_id"):
            RiskAssessment(
                correlation_id="",
                score=50,
                risk_level="Medium",
                priority="Medium",
                reasoning="Test",
                factors=factors,
            )

    def test_score_negative_raises(self) -> None:
        factors = (RiskFactor(name="a", weight=10, contribution=5,
                              description="A"),)
        with pytest.raises(ValueError, match="score"):
            RiskAssessment(
                correlation_id="corr-abc",
                score=-1,
                risk_level="Low",
                priority="Low",
                reasoning="Test",
                factors=factors,
            )

    def test_score_above_100_raises(self) -> None:
        factors = (RiskFactor(name="a", weight=10, contribution=5,
                              description="A"),)
        with pytest.raises(ValueError, match="score"):
            RiskAssessment(
                correlation_id="corr-abc",
                score=101,
                risk_level="High",
                priority="High",
                reasoning="Test",
                factors=factors,
            )

    def test_empty_factors_raises(self) -> None:
        with pytest.raises(ValueError, match="factors"):
            RiskAssessment(
                correlation_id="corr-abc",
                score=50,
                risk_level="Medium",
                priority="Medium",
                reasoning="Test",
                factors=(),
            )


# ===========================================================================
# RiskScorer — score() basic
# ===========================================================================


class TestScoreBasic:
    def test_returns_risk_assessment(self) -> None:
        ef = _make_ef()
        ra = _ENGINE.score(ef)
        assert isinstance(ra, RiskAssessment)

    def test_has_seven_factors(self) -> None:
        ef = _make_ef()
        ra = _ENGINE.score(ef)
        assert len(ra.factors) == 7

    def test_preserves_correlation_id(self) -> None:
        ef = _make_ef(correlation_id="corr-special")
        ra = _ENGINE.score(ef)
        assert ra.correlation_id == "corr-special"

    def test_score_is_integer(self) -> None:
        ef = _make_ef()
        ra = _ENGINE.score(ef)
        assert isinstance(ra.score, int)

    def test_score_in_range_zero_to_hundred(self) -> None:
        ef = _make_ef(severity=Severity.INFORMATIONAL, confidence=0.0)
        assert 0 <= _ENGINE.score(ef).score <= 100
        ef2 = _make_ef(severity=Severity.CRITICAL, confidence=1.0,
                       exploit_likelihood="High",
                       business_impact="Critical",
                       attack_surface="Web Application",
                       scanner_sources=("n", "m", "n2", "n3"),
                       risk_factors=("a", "b", "c", "d"))
        assert 0 <= _ENGINE.score(ef2).score <= 100

    def test_deterministic(self) -> None:
        ef = _make_ef()
        assert _ENGINE.score(ef) == _ENGINE.score(ef)

    def test_reasoning_contains_score(self) -> None:
        ef = _make_ef()
        ra = _ENGINE.score(ef)
        assert str(ra.score) in ra.reasoning

    def test_reasoning_contains_risk_level(self) -> None:
        ef = _make_ef()
        ra = _ENGINE.score(ef)
        assert ra.risk_level in ra.reasoning

    def test_factor_names_are_correct(self) -> None:
        ef = _make_ef()
        ra = _ENGINE.score(ef)
        names = [f.name for f in ra.factors]
        assert names == [
            "severity", "confidence", "exploit_likelihood",
            "business_impact", "attack_surface", "scanner_count",
            "risk_factors",
        ]


# ===========================================================================
# RiskScorer — severity contribution
# ===========================================================================


class TestSeverityContribution:
    def test_critical_contributes_30(self) -> None:
        ef = _make_ef(severity=Severity.CRITICAL)
        ra = _ENGINE.score(ef)
        sev = next(f for f in ra.factors if f.name == "severity")
        assert sev.contribution == 30

    def test_high_contributes_22(self) -> None:
        ef = _make_ef(severity=Severity.HIGH)
        ra = _ENGINE.score(ef)
        sev = next(f for f in ra.factors if f.name == "severity")
        assert sev.contribution == 22

    def test_medium_contributes_14(self) -> None:
        ef = _make_ef(severity=Severity.MEDIUM)
        ra = _ENGINE.score(ef)
        sev = next(f for f in ra.factors if f.name == "severity")
        assert sev.contribution == 14

    def test_low_contributes_6(self) -> None:
        ef = _make_ef(severity=Severity.LOW)
        ra = _ENGINE.score(ef)
        sev = next(f for f in ra.factors if f.name == "severity")
        assert sev.contribution == 6

    def test_informational_contributes_0(self) -> None:
        ef = _make_ef(severity=Severity.INFORMATIONAL)
        ra = _ENGINE.score(ef)
        sev = next(f for f in ra.factors if f.name == "severity")
        assert sev.contribution == 0


# ===========================================================================
# RiskScorer — confidence contribution
# ===========================================================================


class TestConfidenceContribution:
    def test_confidence_1_contributes_15(self) -> None:
        ef = _make_ef(confidence=1.0)
        ra = _ENGINE.score(ef)
        cf = next(f for f in ra.factors if f.name == "confidence")
        assert cf.contribution == 15

    def test_confidence_0_contributes_0(self) -> None:
        ef = _make_ef(confidence=0.0)
        ra = _ENGINE.score(ef)
        cf = next(f for f in ra.factors if f.name == "confidence")
        assert cf.contribution == 0

    def test_confidence_0_5_contributes_7(self) -> None:
        ef = _make_ef(confidence=0.5)
        ra = _ENGINE.score(ef)
        cf = next(f for f in ra.factors if f.name == "confidence")
        assert cf.contribution == 7

    def test_confidence_0_33_contributes_4(self) -> None:
        ef = _make_ef(confidence=0.33)
        ra = _ENGINE.score(ef)
        cf = next(f for f in ra.factors if f.name == "confidence")
        assert cf.contribution == 4

    def test_confidence_0_99_contributes_14(self) -> None:
        ef = _make_ef(confidence=0.99)
        ra = _ENGINE.score(ef)
        cf = next(f for f in ra.factors if f.name == "confidence")
        assert cf.contribution == 14


# ===========================================================================
# RiskScorer — exploit likelihood contribution
# ===========================================================================


class TestExploitLikelihoodContribution:
    def test_high_contributes_15(self) -> None:
        ef = _make_ef(exploit_likelihood="High")
        ra = _ENGINE.score(ef)
        el = next(f for f in ra.factors if f.name == "exploit_likelihood")
        assert el.contribution == 15

    def test_medium_contributes_10(self) -> None:
        ef = _make_ef(exploit_likelihood="Medium")
        ra = _ENGINE.score(ef)
        el = next(f for f in ra.factors if f.name == "exploit_likelihood")
        assert el.contribution == 10

    def test_low_contributes_5(self) -> None:
        ef = _make_ef(exploit_likelihood="Low")
        ra = _ENGINE.score(ef)
        el = next(f for f in ra.factors if f.name == "exploit_likelihood")
        assert el.contribution == 5

    def test_none_contributes_0(self) -> None:
        ef = _make_ef(exploit_likelihood=None)
        ra = _ENGINE.score(ef)
        el = next(f for f in ra.factors if f.name == "exploit_likelihood")
        assert el.contribution == 0


# ===========================================================================
# RiskScorer — business impact contribution
# ===========================================================================


class TestBusinessImpactContribution:
    def test_critical_contributes_15(self) -> None:
        ef = _make_ef(business_impact="Critical")
        ra = _ENGINE.score(ef)
        bi = next(f for f in ra.factors if f.name == "business_impact")
        assert bi.contribution == 15

    def test_high_contributes_11(self) -> None:
        ef = _make_ef(business_impact="High")
        ra = _ENGINE.score(ef)
        bi = next(f for f in ra.factors if f.name == "business_impact")
        assert bi.contribution == 11

    def test_medium_contributes_7(self) -> None:
        ef = _make_ef(business_impact="Medium")
        ra = _ENGINE.score(ef)
        bi = next(f for f in ra.factors if f.name == "business_impact")
        assert bi.contribution == 7

    def test_low_contributes_3(self) -> None:
        ef = _make_ef(business_impact="Low")
        ra = _ENGINE.score(ef)
        bi = next(f for f in ra.factors if f.name == "business_impact")
        assert bi.contribution == 3

    def test_none_contributes_0(self) -> None:
        ef = _make_ef(business_impact=None)
        ra = _ENGINE.score(ef)
        bi = next(f for f in ra.factors if f.name == "business_impact")
        assert bi.contribution == 0


# ===========================================================================
# RiskScorer — attack surface contribution
# ===========================================================================


class TestAttackSurfaceContribution:
    def test_web_application_contributes_10(self) -> None:
        ef = _make_ef(attack_surface="Web Application")
        ra = _ENGINE.score(ef)
        a = next(f for f in ra.factors if f.name == "attack_surface")
        assert a.contribution == 10

    def test_api_contributes_9(self) -> None:
        ef = _make_ef(attack_surface="API")
        ra = _ENGINE.score(ef)
        a = next(f for f in ra.factors if f.name == "attack_surface")
        assert a.contribution == 9

    def test_network_service_contributes_8(self) -> None:
        ef = _make_ef(attack_surface="Network Service")
        ra = _ENGINE.score(ef)
        a = next(f for f in ra.factors if f.name == "attack_surface")
        assert a.contribution == 8

    def test_database_contributes_8(self) -> None:
        ef = _make_ef(attack_surface="Database")
        ra = _ENGINE.score(ef)
        a = next(f for f in ra.factors if f.name == "attack_surface")
        assert a.contribution == 8

    def test_cloud_contributes_7(self) -> None:
        ef = _make_ef(attack_surface="Cloud")
        ra = _ENGINE.score(ef)
        a = next(f for f in ra.factors if f.name == "attack_surface")
        assert a.contribution == 7

    def test_authentication_contributes_7(self) -> None:
        ef = _make_ef(attack_surface="Authentication")
        ra = _ENGINE.score(ef)
        a = next(f for f in ra.factors if f.name == "attack_surface")
        assert a.contribution == 7

    def test_container_contributes_6(self) -> None:
        ef = _make_ef(attack_surface="Container")
        ra = _ENGINE.score(ef)
        a = next(f for f in ra.factors if f.name == "attack_surface")
        assert a.contribution == 6

    def test_file_system_contributes_6(self) -> None:
        ef = _make_ef(attack_surface="File System")
        ra = _ENGINE.score(ef)
        a = next(f for f in ra.factors if f.name == "attack_surface")
        assert a.contribution == 6

    def test_network_infrastructure_contributes_5(self) -> None:
        ef = _make_ef(attack_surface="Network Infrastructure")
        ra = _ENGINE.score(ef)
        a = next(f for f in ra.factors if f.name == "attack_surface")
        assert a.contribution == 5

    def test_dns_contributes_4(self) -> None:
        ef = _make_ef(attack_surface="DNS")
        ra = _ENGINE.score(ef)
        a = next(f for f in ra.factors if f.name == "attack_surface")
        assert a.contribution == 4

    def test_none_contributes_0(self) -> None:
        ef = _make_ef(attack_surface=None)
        ra = _ENGINE.score(ef)
        a = next(f for f in ra.factors if f.name == "attack_surface")
        assert a.contribution == 0


# ===========================================================================
# RiskScorer — scanner count contribution
# ===========================================================================


class TestScannerCountContribution:
    def test_scanner_count_4_contributes_10(self) -> None:
        ef = _make_ef(scanner_sources=("a", "b", "c", "d"))
        ra = _ENGINE.score(ef)
        s = next(f for f in ra.factors if f.name == "scanner_count")
        assert s.contribution == 10

    def test_scanner_count_3_contributes_8(self) -> None:
        ef = _make_ef(scanner_sources=("a", "b", "c"))
        ra = _ENGINE.score(ef)
        s = next(f for f in ra.factors if f.name == "scanner_count")
        assert s.contribution == 8

    def test_scanner_count_2_contributes_6(self) -> None:
        ef = _make_ef(scanner_sources=("a", "b"))
        ra = _ENGINE.score(ef)
        s = next(f for f in ra.factors if f.name == "scanner_count")
        assert s.contribution == 6

    def test_scanner_count_1_contributes_3(self) -> None:
        ef = _make_ef(scanner_sources=("nuclei",))
        ra = _ENGINE.score(ef)
        s = next(f for f in ra.factors if f.name == "scanner_count")
        assert s.contribution == 3

    def test_scanner_count_0_contributes_0(self) -> None:
        ef = _make_ef(scanner_sources=())
        ra = _ENGINE.score(ef)
        s = next(f for f in ra.factors if f.name == "scanner_count")
        assert s.contribution == 0


# ===========================================================================
# RiskScorer — risk factor count contribution
# ===========================================================================


class TestRiskFactorCountContribution:
    def test_risk_factor_count_4_contributes_5(self) -> None:
        ef = _make_ef(risk_factors=("a", "b", "c", "d"))
        ra = _ENGINE.score(ef)
        r = next(f for f in ra.factors if f.name == "risk_factors")
        assert r.contribution == 5

    def test_risk_factor_count_3_contributes_4(self) -> None:
        ef = _make_ef(risk_factors=("a", "b", "c"))
        ra = _ENGINE.score(ef)
        r = next(f for f in ra.factors if f.name == "risk_factors")
        assert r.contribution == 4

    def test_risk_factor_count_2_contributes_3(self) -> None:
        ef = _make_ef(risk_factors=("a", "b"))
        ra = _ENGINE.score(ef)
        r = next(f for f in ra.factors if f.name == "risk_factors")
        assert r.contribution == 3

    def test_risk_factor_count_1_contributes_2(self) -> None:
        ef = _make_ef(risk_factors=("Remote Code Execution",))
        ra = _ENGINE.score(ef)
        r = next(f for f in ra.factors if f.name == "risk_factors")
        assert r.contribution == 2

    def test_risk_factor_count_0_contributes_0(self) -> None:
        ef = _make_ef(risk_factors=())
        ra = _ENGINE.score(ef)
        r = next(f for f in ra.factors if f.name == "risk_factors")
        assert r.contribution == 0


# ===========================================================================
# RiskScorer — total score and risk level
# ===========================================================================


class TestTotalScore:
    def test_minimal_score_is_0(self) -> None:
        ef = _make_ef(severity=Severity.INFORMATIONAL, confidence=0.0,
                       exploit_likelihood=None, business_impact=None,
                       attack_surface=None, scanner_sources=(),
                       risk_factors=())
        ra = _ENGINE.score(ef)
        assert ra.score == 0

    def test_risk_level_informational_at_0(self) -> None:
        ef = _make_ef(severity=Severity.INFORMATIONAL, confidence=0.0,
                       exploit_likelihood=None, business_impact=None,
                       attack_surface=None, scanner_sources=(),
                       risk_factors=())
        ra = _ENGINE.score(ef)
        assert ra.risk_level == "Informational"

    def test_low_risk_at_25(self) -> None:
        # severity=LOW(6) + conf=0.5(7) + lkhd=Low(5) + impact=Low(3) + surface=DNS(4) = 25
        ef = _make_ef(severity=Severity.LOW, confidence=0.50,
                       exploit_likelihood="Low", business_impact="Low",
                       attack_surface="DNS", scanner_sources=(),
                       risk_factors=())
        ra = _ENGINE.score(ef)
        assert ra.score >= 25
        assert ra.risk_level == "Low"

    def test_medium_risk_at_40(self) -> None:
        # MEDIUM(14) + conf=0.6(9) + lkhd=Medium(10) + impact=Medium(7)
        # + surface=NetworkService(8) + scanner=1(3) = 51
        ef = _make_ef(severity=Severity.MEDIUM, confidence=0.60,
                       exploit_likelihood="Medium", business_impact="Medium",
                       attack_surface="Network Service",
                       scanner_sources=("n",),
                       risk_factors=())
        ra = _ENGINE.score(ef)
        assert ra.risk_level == "Medium"

    def test_high_risk_at_60(self) -> None:
        ef = _make_ef(severity=Severity.HIGH, confidence=0.60,
                       exploit_likelihood="Medium", business_impact="Medium",
                       attack_surface="Web Application", scanner_sources=("n",),
                       risk_factors=())
        ra = _ENGINE.score(ef)
        assert ra.risk_level == "High"

    def test_critical_risk_at_80(self) -> None:
        ef = _make_ef(severity=Severity.CRITICAL, confidence=1.0,
                       exploit_likelihood="High", business_impact="Critical",
                       attack_surface="Web Application",
                       scanner_sources=("a", "b", "c", "d"),
                       risk_factors=("a", "b", "c", "d", "e"))
        ra = _ENGINE.score(ef)
        assert ra.risk_level == "Critical"
        assert ra.score >= 80

    def test_score_capped_at_100(self) -> None:
        ef = _make_ef(severity=Severity.CRITICAL, confidence=1.0,
                       exploit_likelihood="High", business_impact="Critical",
                       attack_surface="Web Application",
                       scanner_sources=("a", "b", "c", "d"),
                       risk_factors=("a", "b", "c", "d"))
        ra = _ENGINE.score(ef)
        assert ra.score <= 100


# ===========================================================================
# RiskScorer — priority
# ===========================================================================


class TestPriority:
    def test_critical_priority(self) -> None:
        ef = _make_ef(severity=Severity.CRITICAL, confidence=1.0,
                       exploit_likelihood="High", business_impact="Critical",
                       attack_surface="Web Application",
                       scanner_sources=("a", "b", "c", "d"),
                       risk_factors=("a", "b", "c", "d"))
        ra = _ENGINE.score(ef)
        assert ra.priority == "Critical"

    def test_high_priority(self) -> None:
        ef = _make_ef(severity=Severity.HIGH, confidence=0.80,
                       exploit_likelihood="Medium", business_impact="Medium",
                       attack_surface="Web Application",
                       scanner_sources=("a", "b"),
                       risk_factors=("a", "b"))
        ra = _ENGINE.score(ef)
        assert ra.priority == "High"

    def test_medium_priority(self) -> None:
        # MEDIUM(14) + conf=0.6(9) + lkhd=Medium(10) + impact=Medium(7)
        # + surface=NetworkService(8) + scanner=1(3) = 51
        ef = _make_ef(severity=Severity.MEDIUM, confidence=0.60,
                       exploit_likelihood="Medium", business_impact="Medium",
                       attack_surface="Network Service",
                       scanner_sources=("n",),
                       risk_factors=())
        ra = _ENGINE.score(ef)
        assert ra.priority == "Medium"

    def test_low_priority(self) -> None:
        ef = _make_ef(severity=Severity.LOW, confidence=0.0,
                       exploit_likelihood=None, business_impact=None,
                       attack_surface=None, scanner_sources=(),
                       risk_factors=())
        ra = _ENGINE.score(ef)
        assert ra.priority == "Low"

    def test_informational_low_priority(self) -> None:
        ef = _make_ef(severity=Severity.INFORMATIONAL, confidence=0.0,
                       exploit_likelihood=None, business_impact=None,
                       attack_surface=None, scanner_sources=(),
                       risk_factors=())
        ra = _ENGINE.score(ef)
        assert ra.priority == "Low"

    def test_priority_differs_from_enriched(self) -> None:
        # Enriched priority is "Critical" but risk score may produce "High"
        ef = _make_ef(severity=Severity.CRITICAL, confidence=0.50,
                       exploit_likelihood="Low", business_impact=None,
                       attack_surface=None, scanner_sources=(),
                       risk_factors=())
        ra = _ENGINE.score(ef)
        # Not asserting specific value, just that priority exists
        assert ra.priority in ("Critical", "High", "Medium", "Low")


# ===========================================================================
# RiskScorer — factor ordering
# ===========================================================================


class TestFactorOrdering:
    def test_factors_in_expected_order(self) -> None:
        ef = _make_ef()
        ra = _ENGINE.score(ef)
        names = [f.name for f in ra.factors]
        assert names == [
            "severity", "confidence", "exploit_likelihood",
            "business_impact", "attack_surface", "scanner_count",
            "risk_factors",
        ]


# ===========================================================================
# RiskScorer — deterministic
# ===========================================================================


class TestDeterministic:
    def test_same_input_same_output(self) -> None:
        ef = _make_ef(severity=Severity.CRITICAL, confidence=0.85,
                       exploit_likelihood="High", business_impact="Critical",
                       attack_surface="Web Application",
                       scanner_sources=("n", "m", "n2"),
                       risk_factors=("a", "b"))
        r1 = _ENGINE.score(ef)
        r2 = _ENGINE.score(ef)
        assert r1 == r2

    def test_different_inputs_different_outputs(self) -> None:
        ef1 = _make_ef(severity=Severity.CRITICAL, confidence=1.0)
        ef2 = _make_ef(severity=Severity.INFORMATIONAL, confidence=0.0)
        assert _ENGINE.score(ef1) != _ENGINE.score(ef2)


# ===========================================================================
# RiskScorer — reasoning
# ===========================================================================


class TestReasoning:
    def test_reasoning_includes_all_factors(self) -> None:
        ef = _make_ef(severity=Severity.HIGH, confidence=0.60,
                       exploit_likelihood="Medium", business_impact="Medium",
                       attack_surface="Web Application",
                       scanner_sources=("n", "m"),
                       risk_factors=("a", "b"))
        ra = _ENGINE.score(ef)
        assert "severity=22" in ra.reasoning
        assert "confidence=9" in ra.reasoning
        assert "exploit_likelihood=10" in ra.reasoning
        assert "business_impact=7" in ra.reasoning
        assert "attack_surface=10" in ra.reasoning
        assert "scanner_count=6" in ra.reasoning
        assert "risk_factors=3" in ra.reasoning

    def test_factor_descriptions(self) -> None:
        ef = _make_ef(severity=Severity.CRITICAL, confidence=0.99,
                       exploit_likelihood="High", business_impact="Critical",
                       attack_surface="API", scanner_sources=("a", "b", "c"),
                       risk_factors=("RCE", "XSS"))
        ra = _ENGINE.score(ef)
        descs = [f.description for f in ra.factors]
        assert any("CRITICAL" in d for d in descs)
        assert any("0.99" in d for d in descs)
        assert any("High" in d for d in descs)
        assert any("API" in d or "unknown" in d for d in descs)
        assert any("3 scanner" in d for d in descs)
        assert any("2 risk factor" in d for d in descs)


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_all_none_fields(self) -> None:
        ef = _make_ef(severity=Severity.INFORMATIONAL, confidence=0.0,
                       exploit_likelihood=None, business_impact=None,
                       attack_surface=None, scanner_sources=(),
                       risk_factors=())
        ra = _ENGINE.score(ef)
        assert ra.score == 0
        assert ra.risk_level == "Informational"

    def test_maximum_configuration(self) -> None:
        ef = _make_ef(severity=Severity.CRITICAL, confidence=1.0,
                       exploit_likelihood="High", business_impact="Critical",
                       attack_surface="Web Application",
                       scanner_sources=("a", "b", "c", "d", "e"),
                       risk_factors=("a", "b", "c", "d", "e", "f"))
        ra = _ENGINE.score(ef)
        assert ra.score == 100
        assert ra.risk_level == "Critical"

    def test_many_findings_large_dataset(self) -> None:
        findings = [
            _make_ef(correlation_id=f"corr-{i:04d}",
                      severity=Severity.HIGH, confidence=0.60,
                      exploit_likelihood="Medium", business_impact="High",
                      attack_surface="Web Application",
                      scanner_sources=("nuclei",),
                      risk_factors=("xss",))
            for i in range(100)
        ]
        results = [_ENGINE.score(f) for f in findings]
        assert len(results) == 100
        for r in results:
            assert isinstance(r, RiskAssessment)
            assert 0 <= r.score <= 100

    def test_unknown_attack_surface(self) -> None:
        ef = _make_ef(attack_surface="Quantum Network")
        ra = _ENGINE.score(ef)
        a = next(f for f in ra.factors if f.name == "attack_surface")
        assert a.contribution == 0

    def test_empty_scanner_sources(self) -> None:
        ef = _make_ef(scanner_sources=())
        ra = _ENGINE.score(ef)
        s = next(f for f in ra.factors if f.name == "scanner_count")
        assert s.contribution == 0

    def test_single_risk_factor(self) -> None:
        ef = _make_ef(risk_factors=("Remote Code Execution",))
        ra = _ENGINE.score(ef)
        r = next(f for f in ra.factors if f.name == "risk_factors")
        assert r.contribution == 2

    def test_various_severity_with_all_high_inputs(self) -> None:
        for sev in Severity:
            ef = _make_ef(severity=sev, confidence=1.0,
                           exploit_likelihood="High",
                           business_impact="Critical",
                           attack_surface="Web Application",
                           scanner_sources=("a", "b", "c", "d"),
                           risk_factors=("a", "b", "c", "d"))
            ra = _ENGINE.score(ef)
            assert 0 <= ra.score <= 100
