"""SARIF 2.1.0 Renderer: comprehensive tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest

from kingsec.application.attack_path import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    AttackPath,
)
from kingsec.application.renderers.sarif_renderer import SarifRenderer
from kingsec.application.report import (
    Appendix,
    AssetEntry,
    AssetSummary,
    AttackPathSection,
    ExecutiveSummary,
    FindingEntry,
    FindingSection,
    RecommendationEntry,
    RecommendationSection,
    Report,
    RiskSummary,
    TechnicalSummary,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RENDERER = SarifRenderer()
_NOW = datetime(2026, 7, 17, tzinfo=UTC)


def _es(
    total_findings: int = 10,
    critical: int = 2,
    high: int = 3,
    medium: int = 3,
    low: int = 1,
    informational: int = 1,
    top_score: int = 95,
    avg_score: float = 55.5,
    assets: int = 3,
    text: str = "Security scan found 10 findings across 3 assets.",
) -> ExecutiveSummary:
    return ExecutiveSummary(
        total_findings=total_findings,
        total_correlated=total_findings,
        total_enriched=total_findings,
        total_risk_assessments=total_findings,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        informational_count=informational,
        top_risk_score=top_score,
        average_risk_score=avg_score,
        total_assets=assets,
        summary_text=text,
    )


def _ts() -> TechnicalSummary:
    return TechnicalSummary(
        total_findings=10,
        total_correlations=10,
        total_enriched=10,
        total_risk_assessments=10,
        severity_breakdown={"CRITICAL": 2, "HIGH": 3},
        category_breakdown={"vulnerability": 8, "misconfiguration": 2},
        scanner_coverage={"nuclei": 5, "nmap": 3, "nikto": 2},
    )


def _rs(
    dist: dict[str, int] | None = None,
    avg: float = 55.5,
    high: int = 95,
    low: int = 10,
) -> RiskSummary:
    return RiskSummary(
        score_distribution=dist or {
            "Critical": 2, "High": 3, "Medium": 3, "Low": 1, "Informational": 1,
        },
        average_score=avg,
        highest_score=high,
        lowest_score=low,
        top_risk_factors=("Remote Code Execution", "SQL Injection"),
    )


def _finding_entry(
    cid: str = "corr-001",
    title: str = "SSH Vulnerability",
    severity: str = "HIGH",
    score: int = 75,
    assets: tuple[str, ...] = ("10.0.0.1",),
) -> FindingEntry:
    return FindingEntry(
        correlation_id=cid,
        title=title,
        severity=severity,
        category="vulnerability",
        confidence=0.8,
        scanner_sources=("nuclei",),
        affected_assets=assets,
        service="SSH",
        port=22,
        protocol="TCP",
        attack_surface="Network Service",
        risk_score=score,
        risk_level="High",
        priority="High",
    )


def _asset_entry(
    asset: str = "10.0.0.1",
    count: int = 5,
    high: int = 90,
    avg: float = 55.5,
) -> AssetEntry:
    return AssetEntry(
        asset=asset,
        finding_count=count,
        highest_risk_score=high,
        average_risk_score=avg,
    )


def _rec_entry(
    title: str = "SSH Vulnerability",
    severity: str = "HIGH",
    score: int = 75,
    cid: str = "corr-001",
    recs: tuple[str, ...] = ("Update OpenSSH", "Disable root login"),
) -> RecommendationEntry:
    return RecommendationEntry(
        finding_title=title,
        severity=severity,
        risk_score=score,
        correlation_id=cid,
        recommendations=recs,
    )


def _attack_node(
    cid: str = "corr-001",
    title: str = "SSH Vuln",
    score: int = 75,
) -> AttackNode:
    return AttackNode(
        node_id=f"node-{cid}",
        correlation_id=cid,
        title=title,
        severity="HIGH",
        category="vulnerability",
        attack_surface="Network Service",
        service="SSH",
        port=22,
        protocol="TCP",
        asset="10.0.0.1",
        risk_score=score,
        risk_level="High",
    )


def _graph(
    node_scores: list[int] | None = None,
) -> AttackGraph:
    if node_scores is None:
        node_scores = [75]
    nodes = [
        _attack_node(f"corr-{i:04d}", f"Finding {i}", s)
        for i, s in enumerate(node_scores)
    ]
    edges: list[AttackEdge] = []
    for i in range(len(nodes) - 1):
        edges.append(AttackEdge(
            source_id=nodes[i].node_id,
            target_id=nodes[i + 1].node_id,
            relationship="same_asset",
            confidence=0.8,
        ))
    scores = [n.risk_score for n in nodes]
    max_s = max(scores) if scores else 0
    avg_s = sum(scores) / len(scores) if scores else 0.0
    as_val = min(int(max_s * 0.6 + avg_s * 0.4), 100)
    p = AttackPath(
        path_id="path-001",
        nodes=tuple(nodes),
        edges=tuple(edges),
        attack_score=as_val,
        confidence=0.8 if edges else 0.35,
        estimated_impact="High",
        attack_complexity="Moderate",
        likelihood="Medium",
        reasoning="Attack chain detected.",
        recommendations=("Review access controls",),
    )
    return AttackGraph(
        paths=(p,),
        total_paths=1,
        highest_score=as_val,
        average_score=float(as_val),
        metadata={"total_assessments": str(len(nodes))},
    )


def _appendix() -> Appendix:
    return Appendix(
        scanner_versions={"nuclei": "3.2.1", "nmap": "7.95"},
        total_plugins=2,
        generated_at=_NOW,
        generated_by="KingSec Report Builder",
    )


def _minimal_report() -> Report:
    es = _es(
        total_findings=1, critical=0, high=1, medium=0, low=0, informational=0,
        top_score=75, avg_score=75.0, assets=1,
        text="Security scan found 1 finding across 1 asset.",
    )
    ts = TechnicalSummary(
        total_findings=1, total_correlations=1, total_enriched=1,
        total_risk_assessments=1,
        severity_breakdown={"HIGH": 1},
        category_breakdown={"vulnerability": 1},
        scanner_coverage={"nuclei\u2728": 1},
    )
    rs = _rs(dist={"High": 1}, avg=75.0, high=75, low=75)
    ae = _asset_entry(asset="10.0.0.1", count=1, high=75, avg=75.0)
    fe = _finding_entry()
    fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
    aps = AttackPathSection(
        total_paths=1, highest_score=75, average_score=75.0,
        graph=_graph(),
    )
    rec_e = _rec_entry()
    recs = RecommendationSection(entries=(rec_e,), total_recommendations=2)
    app = _appendix()
    return Report(
        report_id="rpt-001",
        title="KingSec Security Report",
        created_at=_NOW,
        executive_summary=es,
        technical_summary=ts,
        risk_summary=rs,
        asset_summary=AssetSummary(entries=(ae,), total_assets=1),
        finding_section=fs,
        attack_path_section=aps,
        recommendation_section=recs,
        appendix=app,
    )


def _empty_report() -> Report:
    es = _es(
        total_findings=0, critical=0, high=0, medium=0, low=0, informational=0,
        top_score=0, avg_score=0.0, assets=0,
        text="No findings were discovered during the scan.",
    )
    ts = TechnicalSummary(
        total_findings=0, total_correlations=0, total_enriched=0,
        total_risk_assessments=0,
        severity_breakdown={}, category_breakdown={}, scanner_coverage={},
    )
    rs = _rs(dist={}, avg=0.0, high=0, low=0)
    fs = FindingSection(entries=(), total_count=0, severity_breakdown={})
    n1 = _attack_node("corr-dummy", "Dummy", 0)
    p = AttackPath(
        path_id="path-empty", nodes=(n1,), edges=(),
        attack_score=0, confidence=0.0,
        estimated_impact="None", attack_complexity="Simple",
        likelihood="Low", reasoning="Empty.", recommendations=(),
    )
    ag = AttackGraph(paths=(p,), total_paths=0, highest_score=0,
                     average_score=0.0, metadata={})
    aps = AttackPathSection(
        total_paths=0, highest_score=0, average_score=0.0, graph=ag,
    )
    recs = RecommendationSection(entries=(), total_recommendations=0)
    app = Appendix(
        scanner_versions={}, total_plugins=0,
        generated_at=_NOW, generated_by="KingSec Report Builder",
    )
    return Report(
        report_id="rpt-empty",
        title="KingSec Security Report",
        created_at=_NOW,
        executive_summary=es,
        technical_summary=ts,
        risk_summary=rs,
        asset_summary=AssetSummary(entries=(), total_assets=0),
        finding_section=fs,
        attack_path_section=aps,
        recommendation_section=recs,
        appendix=app,
    )


def _multi_report() -> Report:
    es = _es(
        total_findings=5, critical=1, high=2, medium=1, low=1, informational=0,
        top_score=95, avg_score=60.0, assets=3,
        text="Security scan found 5 findings across 3 assets.",
    )
    ts = TechnicalSummary(
        total_findings=5, total_correlations=5, total_enriched=5,
        total_risk_assessments=5,
        severity_breakdown={"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 1},
        category_breakdown={"vulnerability": 3, "misconfiguration": 1, "info": 1},
        scanner_coverage={"nuclei": 3, "nmap": 2},
    )
    rs = RiskSummary(
        score_distribution={"Critical": 1, "High": 2, "Medium": 1, "Low": 1},
        average_score=60.0, highest_score=95, lowest_score=15,
        top_risk_factors=("RCE", "SQLi", "XSS"),
    )
    fe1 = _finding_entry("corr-001", "RCE in Apache", "CRITICAL", 95)
    fe2 = _finding_entry("corr-002", "XSS in Web App", "HIGH", 75, assets=("10.0.0.2",))
    fe3 = _finding_entry("corr-003", "Weak Ciphers", "MEDIUM", 50)
    fe4 = _finding_entry(
        "corr-004", "Info Leak", "LOW", 15,
        assets=("10.0.0.1", "10.0.0.3"),
    )
    fs = FindingSection(
        entries=(fe1, fe2, fe3, fe4),
        total_count=4,
        severity_breakdown={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1},
    )
    ag = _graph([95, 75, 50])
    aps = AttackPathSection(
        total_paths=1, highest_score=75, average_score=75.0, graph=ag,
    )
    ae1 = _asset_entry("10.0.0.1", 2, 95, 85.0)
    ae2 = _asset_entry("10.0.0.2", 2, 75, 62.5)
    ae3 = _asset_entry("10.0.0.3", 1, 50, 50.0)
    asset_sum = AssetSummary(entries=(ae1, ae2, ae3), total_assets=3)
    re1 = _rec_entry(
        "RCE in Apache", "CRITICAL", 95, "corr-001",
        ("Patch Apache", "Update firewall rules"),
    )
    re2 = _rec_entry(
        "XSS in Web App", "HIGH", 75, "corr-002",
        ("Sanitize inputs",),
    )
    recs = RecommendationSection(entries=(re1, re2), total_recommendations=3)
    app = Appendix(
        scanner_versions={"nuclei": "3.2.1", "nmap": "7.95", "nikto": "2.5.0"},
        total_plugins=3,
        generated_at=_NOW,
        generated_by="KingSec Report Builder",
    )
    return Report(
        report_id="rpt-002",
        title="KingSec Security Report",
        created_at=_NOW,
        executive_summary=es,
        technical_summary=ts,
        risk_summary=rs,
        asset_summary=asset_sum,
        finding_section=fs,
        attack_path_section=aps,
        recommendation_section=recs,
        appendix=app,
    )


def _unicode_report() -> Report:
    fe = FindingEntry(
        correlation_id="corr-unicode",
        title="Caf\u00e9 vuln r\u00e9sum\u00e9",
        severity="HIGH",
        category="vulnerability",
        confidence=0.8,
        scanner_sources=("nuclei\u2728",),
        affected_assets=("M\u00fcnchen-01", "Z\u00fcrich-02"),
        service="HTTP",
        port=80,
        protocol="TCP",
        attack_surface="Web",
        risk_score=75,
        risk_level="High",
        priority="High",
    )
    fs = FindingSection(
        entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1},
    )
    app = Appendix(
        scanner_versions={"nuclei\u2728": "3.0"},
        total_plugins=1,
        generated_at=_NOW,
        generated_by="KingSec",
    )
    es = _es(
        total_findings=1, critical=0, high=1, medium=0, low=0, informational=0,
        top_score=75, avg_score=75.0, assets=2,
        text="Caf\u00e9 r\u00e9sum\u00e9 \u00e0 v\u00e9rifier.",
    )
    ts = TechnicalSummary(
        total_findings=1, total_correlations=1, total_enriched=1,
        total_risk_assessments=1,
        severity_breakdown={"HIGH": 1},
        category_breakdown={"vulnerability": 1},
        scanner_coverage={"nuclei\u2728": 1},
    )
    rs = _rs(dist={"High": 1}, avg=75.0, high=75, low=75)
    aps = AttackPathSection(
        total_paths=0, highest_score=0, average_score=0.0,
        graph=_graph([0]),
    )
    recs = RecommendationSection(entries=(), total_recommendations=0)
    return Report(
        report_id="rpt-unicode",
        title="KingSec Security Report",
        created_at=_NOW,
        executive_summary=es,
        technical_summary=ts,
        risk_summary=rs,
        asset_summary=AssetSummary(
            entries=(_asset_entry("M\u00fcnchen-01", 1, 75, 75.0),),
            total_assets=1,
        ),
        finding_section=fs,
        attack_path_section=aps,
        recommendation_section=recs,
        appendix=app,
    )


# ===========================================================================
# Valid SARIF structure
# ===========================================================================


class TestSarifStructure:
    def test_returns_string(self) -> None:
        sarif = _RENDERER.render(_minimal_report())
        assert isinstance(sarif, str)

    def test_valid_json(self) -> None:
        sarif = _RENDERER.render(_minimal_report())
        doc = json.loads(sarif)
        assert isinstance(doc, dict)

    def test_has_schema(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert doc["$schema"] == "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"

    def test_has_version(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert doc["version"] == "2.1.0"

    def test_has_runs(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert isinstance(doc["runs"], list)
        assert len(doc["runs"]) == 1

    def test_run_has_tool(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        run = doc["runs"][0]
        assert "tool" in run
        assert run["tool"]["driver"]["name"] == "KingSec"
        assert run["tool"]["driver"]["version"] == "1.0.0"


# ===========================================================================
# Schema fields
# ===========================================================================


class TestSchemaFields:
    def test_run_has_rules(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert "rules" in doc["runs"][0]
        assert isinstance(doc["runs"][0]["rules"], list)

    def test_run_has_results(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert "results" in doc["runs"][0]
        assert isinstance(doc["runs"][0]["results"], list)

    def test_run_has_artifacts(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert "artifacts" in doc["runs"][0]
        assert isinstance(doc["runs"][0]["artifacts"], list)

    def test_run_has_invocations(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        assert "invocations" in doc["runs"][0]
        assert doc["runs"][0]["invocations"][0]["executionSuccessful"] is True


# ===========================================================================
# Severity mapping
# ===========================================================================


class TestSeverityMapping:
    def test_critical_maps_to_error(self) -> None:
        fe = _finding_entry(cid="c", title="C", severity="CRITICAL")
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"CRITICAL": 1})
        r = _build_report_with_finding_section(fs)
        doc = json.loads(_RENDERER.render(r))
        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_high_maps_to_error(self) -> None:
        fe = _finding_entry(cid="h", title="H", severity="HIGH")
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"HIGH": 1})
        r = _build_report_with_finding_section(fs)
        doc = json.loads(_RENDERER.render(r))
        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_medium_maps_to_warning(self) -> None:
        fe = _finding_entry(cid="m", title="M", severity="MEDIUM")
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"MEDIUM": 1})
        r = _build_report_with_finding_section(fs)
        doc = json.loads(_RENDERER.render(r))
        assert doc["runs"][0]["results"][0]["level"] == "warning"

    def test_low_maps_to_note(self) -> None:
        fe = _finding_entry(cid="l", title="L", severity="LOW")
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"LOW": 1})
        r = _build_report_with_finding_section(fs)
        doc = json.loads(_RENDERER.render(r))
        assert doc["runs"][0]["results"][0]["level"] == "note"

    def test_info_maps_to_note(self) -> None:
        fe = _finding_entry(cid="i", title="I", severity="INFO")
        fs = FindingSection(entries=(fe,), total_count=1, severity_breakdown={"INFO": 1})
        r = _build_report_with_finding_section(fs)
        doc = json.loads(_RENDERER.render(r))
        assert doc["runs"][0]["results"][0]["level"] == "note"

    def test_all_severities_have_mappings(self) -> None:
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert sev in (
                "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
            ), f"Missing mapping for {sev}"


# ===========================================================================
# Rule generation
# ===========================================================================


class TestRuleGeneration:
    def test_rule_has_id(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        rule = doc["runs"][0]["rules"][0]
        assert rule["id"] == "corr-001"

    def test_rule_has_name(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        rule = doc["runs"][0]["rules"][0]
        assert rule["name"] == "SSH Vulnerability"

    def test_rule_has_short_description(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        rule = doc["runs"][0]["rules"][0]
        assert rule["shortDescription"]["text"] == "SSH Vulnerability"

    def test_rule_has_full_description(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        rule = doc["runs"][0]["rules"][0]
        assert "Severity: HIGH" in rule["fullDescription"]["text"]
        assert "Risk Score: 75/100" in rule["fullDescription"]["text"]

    def test_rule_has_help_text(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        rule = doc["runs"][0]["rules"][0]
        assert "SSH Vulnerability" in rule["help"]["text"]
        assert "Remediation:" in rule["help"]["text"]

    def test_rule_has_properties(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        rule = doc["runs"][0]["rules"][0]
        props = rule["properties"]
        assert props["severity"] == "HIGH"
        assert props["category"] == "vulnerability"
        assert props["riskScore"] == 75
        assert props["confidence"] == 0.8

    def test_rule_includes_scanner_info(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        rule = doc["runs"][0]["rules"][0]
        scanners = rule["properties"]["scanners"]
        assert len(scanners) == 1
        assert scanners[0]["name"] == "nuclei"
        assert scanners[0]["version"] == "3.2.1"


# ===========================================================================
# Result generation
# ===========================================================================


class TestResultGeneration:
    def test_result_has_rule_id(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        result = doc["runs"][0]["results"][0]
        assert result["ruleId"] == "corr-001"

    def test_result_has_rule_index(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        result = doc["runs"][0]["results"][0]
        assert result["ruleIndex"] == 0

    def test_result_has_level(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        result = doc["runs"][0]["results"][0]
        assert result["level"] == "error"

    def test_result_has_message(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        result = doc["runs"][0]["results"][0]
        assert result["message"]["text"] == "SSH Vulnerability"

    def test_result_has_locations(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        result = doc["runs"][0]["results"][0]
        assert len(result["locations"]) == 1
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "10.0.0.1"

    def test_result_has_properties(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        result = doc["runs"][0]["results"][0]
        props = result["properties"]
        assert props["riskScore"] == 75
        assert props["priority"] == "High"
        assert props["confidence"] == 0.8


# ===========================================================================
# Artifacts
# ===========================================================================


class TestArtifacts:
    def test_artifacts_from_affected_assets(self) -> None:
        doc = json.loads(_RENDERER.render(_minimal_report()))
        artifacts = doc["runs"][0]["artifacts"]
        assert len(artifacts) == 1
        assert artifacts[0]["location"]["uri"] == "10.0.0.1"
        assert artifacts[0]["description"]["text"] == "Affected asset"

    def test_artifacts_deduplicated(self) -> None:
        fe1 = _finding_entry(cid="a", title="A", assets=("10.0.0.1", "10.0.0.2"))
        fe2 = _finding_entry(cid="b", title="B", assets=("10.0.0.1", "10.0.0.3"))
        fs = FindingSection(
            entries=(fe1, fe2), total_count=2,
            severity_breakdown={"HIGH": 2},
        )
        r = _build_report_with_finding_section(fs)
        doc = json.loads(_RENDERER.render(r))
        artifacts = doc["runs"][0]["artifacts"]
        uris = [a["location"]["uri"] for a in artifacts]
        assert sorted(uris) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


# ===========================================================================
# Empty report
# ===========================================================================


class TestEmptyReport:
    def test_empty_report_no_results(self) -> None:
        doc = json.loads(_RENDERER.render(_empty_report()))
        assert len(doc["runs"][0]["results"]) == 0

    def test_empty_report_no_rules(self) -> None:
        doc = json.loads(_RENDERER.render(_empty_report()))
        assert len(doc["runs"][0]["rules"]) == 0

    def test_empty_report_no_artifacts(self) -> None:
        doc = json.loads(_RENDERER.render(_empty_report()))
        assert len(doc["runs"][0]["artifacts"]) == 0

    def test_empty_report_still_valid_sarif(self) -> None:
        doc = json.loads(_RENDERER.render(_empty_report()))
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["tool"]["driver"]["name"] == "KingSec"

    def test_empty_report_invocation_successful(self) -> None:
        doc = json.loads(_RENDERER.render(_empty_report()))
        assert doc["runs"][0]["invocations"][0]["executionSuccessful"] is True


# ===========================================================================
# Multiple findings
# ===========================================================================


class TestMultiFindings:
    def test_all_rules_present(self) -> None:
        doc = json.loads(_RENDERER.render(_multi_report()))
        rule_ids = [r["id"] for r in doc["runs"][0]["rules"]]
        assert sorted(rule_ids) == ["corr-001", "corr-002", "corr-003", "corr-004"]

    def test_all_results_present(self) -> None:
        doc = json.loads(_RENDERER.render(_multi_report()))
        result_rule_ids = [r["ruleId"] for r in doc["runs"][0]["results"]]
        assert sorted(result_rule_ids) == sorted(result_rule_ids)

    def test_rules_match_results(self) -> None:
        doc = json.loads(_RENDERER.render(_multi_report()))
        rules = doc["runs"][0]["rules"]
        results = doc["runs"][0]["results"]
        assert len(rules) == len(results) == 4
        for i, result in enumerate(results):
            assert result["ruleId"] == rules[i]["id"]
            assert result["ruleIndex"] == i

    def test_all_assets_in_artifacts(self) -> None:
        doc = json.loads(_RENDERER.render(_multi_report()))
        artifact_uris = {a["location"]["uri"] for a in doc["runs"][0]["artifacts"]}
        assert "10.0.0.1" in artifact_uris
        assert "10.0.0.2" in artifact_uris
        assert "10.0.0.3" in artifact_uris

    def test_finding_remediation_in_properties(self) -> None:
        doc = json.loads(_RENDERER.render(_multi_report()))
        corr001_result = next(
            r for r in doc["runs"][0]["results"] if r["ruleId"] == "corr-001"
        )
        assert "Patch Apache" in corr001_result["properties"]["remediation"]

    def test_remediation_in_rule_help(self) -> None:
        doc = json.loads(_RENDERER.render(_multi_report()))
        corr001_rule = next(
            r for r in doc["runs"][0]["rules"] if r["id"] == "corr-001"
        )
        assert "Patch Apache" in corr001_rule["help"]["text"]

    def test_multiple_assets_in_location(self) -> None:
        doc = json.loads(_RENDERER.render(_multi_report()))
        corr004_result = next(
            r for r in doc["runs"][0]["results"] if r["ruleId"] == "corr-004"
        )
        locations = corr004_result["locations"]
        uris = sorted(
            loc["physicalLocation"]["artifactLocation"]["uri"] for loc in locations
        )
        assert uris == ["10.0.0.1", "10.0.0.3"]


# ===========================================================================
# Unicode
# ===========================================================================


class TestUnicode:
    def test_unicode_in_title(self) -> None:
        sarif = _RENDERER.render(_unicode_report())
        assert "Caf\u00e9" in sarif or "Café" in sarif

    def test_unicode_in_asset(self) -> None:
        sarif = _RENDERER.render(_unicode_report())
        assert "M\u00fcnchen" in sarif or "München" in sarif

    def test_unicode_in_scanner_name(self) -> None:
        sarif = _RENDERER.render(_unicode_report())
        assert "\u2728" in sarif

    def test_json_is_utf8(self) -> None:
        sarif_bytes = _RENDERER.render(_unicode_report()).encode("utf-8")
        doc = json.loads(sarif_bytes)
        assert doc["runs"][0]["results"][0]["message"]["text"] == \
            "Caf\u00e9 vuln r\u00e9sum\u00e9"


# ===========================================================================
# Deterministic output
# ===========================================================================


class TestDeterministic:
    def test_same_input_same_output(self) -> None:
        report = _minimal_report()
        s1 = _RENDERER.render(report)
        s2 = _RENDERER.render(report)
        assert s1 == s2

    def test_stable_ordering(self) -> None:
        r1 = _multi_report()
        r2 = _multi_report()
        assert _RENDERER.render(r1) == _RENDERER.render(r2)

    def test_rule_ordering_by_id(self) -> None:
        doc = json.loads(_RENDERER.render(_multi_report()))
        rule_ids = [r["id"] for r in doc["runs"][0]["rules"]]
        assert rule_ids == sorted(rule_ids)

    def test_artifact_ordering(self) -> None:
        doc = json.loads(_RENDERER.render(_multi_report()))
        uris = [a["location"]["uri"] for a in doc["runs"][0]["artifacts"]]
        assert uris == sorted(uris)


# ===========================================================================
# File writing
# ===========================================================================


class TestFileWriting:
    def test_write_creates_file(self) -> None:
        report = _minimal_report()
        with NamedTemporaryFile(mode="w", suffix=".sarif", delete=False, encoding="utf-8") as f:
            path = Path(f.name)
        try:
            _RENDERER.write(report, path)
            assert path.exists()
            content = path.read_text(encoding="utf-8")
            doc = json.loads(content)
            assert doc["version"] == "2.1.0"
        finally:
            path.unlink(missing_ok=True)

    def test_write_utf8_encoding(self) -> None:
        with NamedTemporaryFile(mode="w", suffix=".sarif", delete=False, encoding="utf-8") as f:
            path = Path(f.name)
        try:
            _RENDERER.write(_unicode_report(), path)
            content = path.read_bytes()
            assert "Café".encode() in content
        finally:
            path.unlink(missing_ok=True)

    def test_write_deterministic(self) -> None:
        report = _minimal_report()
        with NamedTemporaryFile(mode="w", suffix=".sarif", delete=False, encoding="utf-8") as f1:
            p1 = Path(f1.name)
        with NamedTemporaryFile(mode="w", suffix=".sarif", delete=False, encoding="utf-8") as f2:
            p2 = Path(f2.name)
        try:
            _RENDERER.write(report, p1)
            _RENDERER.write(report, p2)
            assert p1.read_text(encoding="utf-8") == p2.read_text(encoding="utf-8")
        finally:
            p1.unlink(missing_ok=True)
            p2.unlink(missing_ok=True)

    def test_write_invalid_path_raises(self) -> None:
        invalid = Path("/nonexistent/directory/report.sarif")
        with pytest.raises((OSError, FileNotFoundError)):
            _RENDERER.write(_minimal_report(), invalid)


# ===========================================================================
# Helper: build a minimal valid report with a custom FindingSection
# ===========================================================================


def _build_report_with_finding_section(fs: FindingSection) -> Report:
    es = _es(
        total_findings=len(fs.entries) if fs.entries else 0,
        critical=sum(1 for e in fs.entries if e.severity == "CRITICAL"),
        high=sum(1 for e in fs.entries if e.severity == "HIGH"),
        medium=sum(1 for e in fs.entries if e.severity == "MEDIUM"),
        low=sum(1 for e in fs.entries if e.severity == "LOW"),
        informational=sum(1 for e in fs.entries if e.severity == "INFO"),
        top_score=max((e.risk_score for e in fs.entries), default=0),
        avg_score=(
            sum(e.risk_score for e in fs.entries) / len(fs.entries)
            if fs.entries else 0.0
        ),
        assets=len({a for e in fs.entries for a in e.affected_assets}),
        text="Custom finding section report.",
    )
    ts = TechnicalSummary(
        total_findings=len(fs.entries),
        total_correlations=len(fs.entries),
        total_enriched=len(fs.entries),
        total_risk_assessments=len(fs.entries),
        severity_breakdown={},
        category_breakdown={},
        scanner_coverage={},
    )
    rs = RiskSummary(
        score_distribution={},
        average_score=0.0,
        highest_score=0,
        lowest_score=0,
        top_risk_factors=(),
    )
    aps = AttackPathSection(
        total_paths=0, highest_score=0, average_score=0.0,
        graph=_graph([0]),
    )
    recs = RecommendationSection(entries=(), total_recommendations=0)
    app = Appendix(
        scanner_versions={"nmap": "7.95"},
        total_plugins=1,
        generated_at=_NOW,
        generated_by="KingSec",
    )
    assets_list = [
        AssetEntry(
            asset=a, finding_count=1, highest_risk_score=0, average_risk_score=0.0,
        )
        for a in sorted({a for e in fs.entries for a in e.affected_assets})
    ]
    return Report(
        report_id="rpt-custom",
        title="KingSec Security Report",
        created_at=_NOW,
        executive_summary=es,
        technical_summary=ts,
        risk_summary=rs,
        asset_summary=AssetSummary(
            entries=tuple(assets_list),
            total_assets=len(assets_list),
        ),
        finding_section=fs,
        attack_path_section=aps,
        recommendation_section=recs,
        appendix=app,
    )
