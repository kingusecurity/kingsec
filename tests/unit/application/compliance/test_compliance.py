from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.compliance import (
    ComplianceCoverageCalculator,
    ComplianceGapAnalyzer,
    ComplianceMapper,
    ComplianceReportGenerator,
)
from kingsec.domain.compliance import (
    ComplianceFramework,
    ComplianceReport,
    ComplianceStatus,
    ControlId,
    FindingControlMapping,
    FrameworkControl,
)
from kingsec.domain.enums import FindingStatus, Severity
from kingsec.domain.finding import Finding
from kingsec.domain.identifiers import FindingId


class TestComplianceMapper:
    def setup_method(self) -> None:
        self.mapper = ComplianceMapper()

    def _make_finding(self, title: str, description: str, severity: Severity = Severity.MEDIUM) -> Finding:
        fid = FindingId.generate()
        return Finding.reconstitute(
            finding_id=fid,
            title=title,
            description=description,
            severity=severity,
            status=FindingStatus.OPEN,
            discovered_at=datetime.now(UTC),
        )

    def test_map_missing_security_headers(self) -> None:
        f = self._make_finding("Missing Security Headers", "X-Frame-Options not set")
        controls = self.mapper.map_finding(f)
        assert len(controls) >= 2
        frameworks = {c.framework for c in controls}
        assert ComplianceFramework.OWASP_TOP_10 in frameworks
        assert ComplianceFramework.CIS_V8 in frameworks

    def test_map_sql_injection(self) -> None:
        f = self._make_finding("SQL Injection Vulnerability", "sqli in login form")
        controls = self.mapper.map_finding(f)
        assert len(controls) >= 2
        frameworks = {c.framework for c in controls}
        assert ComplianceFramework.CWE in frameworks
        assert any("CWE-89" in str(c.control_id) for c in controls)

    def test_map_weak_password(self) -> None:
        f = self._make_finding("Weak Password Policy", "minimum password length is 4")
        controls = self.mapper.map_finding(f)
        assert len(controls) >= 2
        assert any(c.framework == ComplianceFramework.CIS_V8 for c in controls)
        assert any(c.framework == ComplianceFramework.NIST_CSF_2 for c in controls)

    def test_map_unpatched_component(self) -> None:
        f = self._make_finding("Unpatched Apache Server", "old version with known vulnerabilities")
        controls = self.mapper.map_finding(f)
        assert len(controls) >= 2
        assert any(c.framework == ComplianceFramework.OWASP_TOP_10 for c in controls)
        assert any(c.framework == ComplianceFramework.CIS_V8 for c in controls)

    def test_map_no_match(self) -> None:
        f = self._make_finding("Some harmless info", "just an informational note")
        controls = self.mapper.map_finding(f)
        assert len(controls) == 0

    def test_map_all(self) -> None:
        findings = [
            self._make_finding("Missing Security Headers", "no CSP header"),
            self._make_finding("SQL Injection", "sqli in search"),
            self._make_finding("Unknown harmless thing", "nothing to see"),
        ]
        mappings = self.mapper.map_all(findings)
        assert len(mappings) == 3
        assert mappings[0].finding_title == "Missing Security Headers"
        assert len(mappings[0].controls) > 0
        assert len(mappings[2].controls) == 0

    def test_get_framework_controls(self) -> None:
        controls = self.mapper.get_framework_controls(ComplianceFramework.OWASP_TOP_10)
        assert len(controls) == 10
        assert any(c.control_id.value == "A01" for c in controls)
        assert any(c.control_id.value == "A05" for c in controls)


class TestComplianceCoverageCalculator:
    def setup_method(self) -> None:
        self.calc = ComplianceCoverageCalculator()
        self.mapper = ComplianceMapper()

    def test_calculate_basic(self) -> None:
        ctrl1 = FrameworkControl(
            framework=ComplianceFramework.OWASP_TOP_10,
            control_id=ControlId("A01"),
            title="Broken Access Control",
            description="",
            category="",
        )
        mappings = [
            FindingControlMapping(
                finding_id="f1",
                finding_title="Test",
                severity="medium",
                controls=(ctrl1,),
            )
        ]
        coverages = self.calc.calculate(mappings, [ComplianceFramework.OWASP_TOP_10])
        assert len(coverages) == 1
        assert coverages[0].framework == ComplianceFramework.OWASP_TOP_10
        assert coverages[0].total_controls == 10
        assert coverages[0].passed == 1
        assert coverages[0].not_assessed == 9

    def test_calculate_multiple_frameworks(self) -> None:
        ctrl_owasp = FrameworkControl(
            framework=ComplianceFramework.OWASP_TOP_10,
            control_id=ControlId("A01"),
            title="Broken Access Control",
            description="",
            category="",
        )
        ctrl_cis = FrameworkControl(
            framework=ComplianceFramework.CIS_V8,
            control_id=ControlId("4.1"),
            title="Secure configuration",
            description="",
            category="",
        )
        mappings = [
            FindingControlMapping(
                finding_id="f1",
                finding_title="Test",
                severity="medium",
                controls=(ctrl_owasp, ctrl_cis),
            )
        ]
        coverages = self.calc.calculate(mappings)
        owasp = next(c for c in coverages if c.framework == ComplianceFramework.OWASP_TOP_10)
        cis = next(c for c in coverages if c.framework == ComplianceFramework.CIS_V8)
        assert owasp.passed == 1
        assert owasp.not_assessed == owasp.total_controls - 1
        assert cis.passed == 1

    def test_calculate_empty_mappings(self) -> None:
        coverages = self.calc.calculate([], [ComplianceFramework.OWASP_TOP_10])
        assert len(coverages) == 1
        assert coverages[0].passed == 0
        assert coverages[0].not_assessed == 10

    def test_get_unmapped_controls(self) -> None:
        ctrl = FrameworkControl(
            framework=ComplianceFramework.OWASP_TOP_10,
            control_id=ControlId("A01"),
            title="Broken Access Control",
            description="",
            category="",
        )
        mappings = [
            FindingControlMapping(
                finding_id="f1",
                finding_title="Test",
                severity="medium",
                controls=(ctrl,),
            )
        ]
        unmapped = self.calc.get_unmapped_controls(ComplianceFramework.OWASP_TOP_10, mappings)
        assert len(unmapped) == 9
        assert all(c.control_id.value != "A01" for c in unmapped)

    def test_coverage_percent(self) -> None:
        from kingsec.domain.compliance import FrameworkCoverage
        fc = FrameworkCoverage(
            framework=ComplianceFramework.OWASP_TOP_10,
            total_controls=10,
            passed=5,
            failed=0,
            not_assessed=5,
        )
        assert fc.coverage_percent == 50.0


class TestComplianceGapAnalyzer:
    def setup_method(self) -> None:
        self.analyzer = ComplianceGapAnalyzer()
        self.mapper = ComplianceMapper()

    def test_analyze_gaps(self) -> None:
        ctrl = FrameworkControl(
            framework=ComplianceFramework.OWASP_TOP_10,
            control_id=ControlId("A01"),
            title="Broken Access Control",
            description="",
            category="",
        )
        mappings = [
            FindingControlMapping(
                finding_id="f1",
                finding_title="Test",
                severity="medium",
                controls=(ctrl,),
            )
        ]
        gaps = self.analyzer.analyze(ComplianceFramework.OWASP_TOP_10, mappings)
        assert len(gaps) == 9
        assert all(g.status == ComplianceStatus.NOT_ASSESSED for g in gaps)
        assert all(g.mapped_findings == () for g in gaps)

    def test_analyze_all(self) -> None:
        mappings: list[FindingControlMapping] = []
        result = self.analyzer.analyze_all(mappings, [ComplianceFramework.OWASP_TOP_10])
        assert len(result) == 1
        assert len(result["owasp_top_10"]) == 10

    def test_gap_has_recommendation(self) -> None:
        ctrl = FrameworkControl(
            framework=ComplianceFramework.OWASP_TOP_10,
            control_id=ControlId("A03"),
            title="Injection",
            description="",
            category="",
        )
        mappings = [
            FindingControlMapping(
                finding_id="f1",
                finding_title="Test",
                severity="medium",
                controls=(ctrl,),
            )
        ]
        gaps = self.analyzer.analyze(ComplianceFramework.OWASP_TOP_10, mappings)
        for g in gaps:
            assert "Assess control" in g.recommendation


class TestComplianceReportGenerator:
    def setup_method(self) -> None:
        self.mapper = ComplianceMapper()
        self.calc = ComplianceCoverageCalculator()
        self.gap = ComplianceGapAnalyzer()
        self.generator = ComplianceReportGenerator(self.mapper, self.calc, self.gap)

    def test_generate_executive_report(self) -> None:
        mappings = [
            FindingControlMapping(
                finding_id="f1",
                finding_title="Test Finding",
                severity="medium",
                controls=(
                    FrameworkControl(
                        framework=ComplianceFramework.OWASP_TOP_10,
                        control_id=ControlId("A01"),
                        title="Broken Access Control",
                        description="",
                        category="",
                    ),
                ),
            )
        ]
        report = self.generator.generate(
            assessment_id="asmt-123",
            target="10.0.0.1",
            mappings=mappings,
            enabled_frameworks=[ComplianceFramework.OWASP_TOP_10],
        )
        assert isinstance(report, ComplianceReport)
        assert report.assessment_id == "asmt-123"
        assert report.target == "10.0.0.1"
        assert len(report.framework_coverages) == 1
        assert report.framework_coverages[0].passed == 1

    def test_generate_executive_output(self) -> None:
        mappings = [
            FindingControlMapping(
                finding_id="f1",
                finding_title="Finding",
                severity="medium",
                controls=(),
            )
        ]
        report = self.generator.generate(
            assessment_id="asmt-1",
            target="test.local",
            mappings=mappings,
            enabled_frameworks=[ComplianceFramework.OWASP_TOP_10],
        )
        exec_report = self.generator.generate_executive(report)
        assert "overall_coverage_percent" in exec_report
        assert "frameworks" in exec_report
        assert "recommendations" in exec_report

    def test_generate_technical_output(self) -> None:
        mappings = [
            FindingControlMapping(
                finding_id="f1",
                finding_title="Finding",
                severity="high",
                controls=(
                    FrameworkControl(
                        framework=ComplianceFramework.OWASP_TOP_10,
                        control_id=ControlId("A01"),
                        title="Broken Access Control",
                        description="",
                        category="Access Control",
                    ),
                ),
            )
        ]
        report = self.generator.generate(
            assessment_id="asmt-2",
            target="test.local",
            mappings=mappings,
            enabled_frameworks=[ComplianceFramework.OWASP_TOP_10],
        )
        tech = self.generator.generate_technical(report)
        assert "finding_mappings" in tech
        assert len(tech["finding_mappings"]) == 1

    def test_generate_gap_remediation_output(self) -> None:
        mappings = [
            FindingControlMapping(
                finding_id="f1",
                finding_title="Finding",
                severity="low",
                controls=(),
            )
        ]
        report = self.generator.generate(
            assessment_id="asmt-3",
            target="test.local",
            mappings=mappings,
            enabled_frameworks=[ComplianceFramework.OWASP_TOP_10],
        )
        gap = self.generator.generate_gap_remediation(report)
        assert "total_gaps" in gap
        assert gap["total_gaps"] > 0
        assert len(gap["gaps"]) > 0
