from __future__ import annotations

import re
from collections.abc import Sequence

from kingsec.domain.compliance import ComplianceFramework, ControlId, FindingControlMapping, FrameworkControl
from kingsec.domain.finding import Finding

from .framework_definitions import FRAMEWORK_DEFINITIONS

_KEYWORD_CONTROL_MAP: list[tuple[frozenset[str], ComplianceFramework, str, str]] = [
    (frozenset({"missing", "security", "header"}), ComplianceFramework.OWASP_TOP_10, "A05", "Security Misconfiguration"),
    (frozenset({"missing", "security", "headers"}), ComplianceFramework.OWASP_TOP_10, "A05", "Security Misconfiguration"),
    (frozenset({"missing", "security", "header"}), ComplianceFramework.CIS_V8, "4.1", "Secure configuration process"),
    (frozenset({"missing", "security", "headers"}), ComplianceFramework.CIS_V8, "4.1", "Secure configuration process"),
    (frozenset({"missing", "security", "header"}), ComplianceFramework.NIST_CSF_2, "PR.DS-5", "Protections against data leaks"),
    (frozenset({"missing", "security", "headers"}), ComplianceFramework.NIST_CSF_2, "PR.DS-5", "Protections against data leaks"),
    (frozenset({"missing", "security", "header"}), ComplianceFramework.PCI_DSS_4, "6.5", "Web application security"),
    (frozenset({"missing", "security", "headers"}), ComplianceFramework.PCI_DSS_4, "6.5", "Web application security"),
    (frozenset({"sql", "injection", "sqli"}), ComplianceFramework.OWASP_TOP_10, "A03", "Injection"),
    (frozenset({"sql", "injection", "sqli"}), ComplianceFramework.CWE, "CWE-89", "SQL Injection"),
    (frozenset({"sql", "injection", "sqli"}), ComplianceFramework.CIS_V8, "16.3", "Perform code review"),
    (frozenset({"cross", "site", "scripting", "xss"}), ComplianceFramework.OWASP_TOP_10, "A03", "Injection"),
    (frozenset({"cross", "site", "scripting", "xss"}), ComplianceFramework.CWE, "CWE-79", "Cross-site scripting"),
    (frozenset({"idor", "insecure", "direct", "object"}), ComplianceFramework.OWASP_TOP_10, "A01", "Broken Access Control"),
    (frozenset({"idor", "insecure", "direct", "object"}), ComplianceFramework.CWE, "CWE-639", "Authorization Bypass"),
    (frozenset({"broken", "access", "control"}), ComplianceFramework.OWASP_TOP_10, "A01", "Broken Access Control"),
    (frozenset({"broken", "access", "control"}), ComplianceFramework.CWE, "CWE-284", "Improper Access Control"),
    (frozenset({"broken", "access", "control"}), ComplianceFramework.CIS_V8, "6.1", "Access control process"),
    (frozenset({"weak", "password"}), ComplianceFramework.OWASP_TOP_10, "A07", "Identification and Authentication Failures"),
    (frozenset({"weak", "password"}), ComplianceFramework.CWE, "CWE-521", "Weak Password Requirements"),
    (frozenset({"weak", "password"}), ComplianceFramework.CIS_V8, "5.2", "Use unique passwords"),
    (frozenset({"weak", "password"}), ComplianceFramework.NIST_CSF_2, "PR.AC-1", "Identity and credential management"),
    (frozenset({"weak", "password"}), ComplianceFramework.PCI_DSS_4, "8.3", "Password security"),
    (frozenset({"default", "credential"}), ComplianceFramework.OWASP_TOP_10, "A05", "Security Misconfiguration"),
    (frozenset({"default", "credential"}), ComplianceFramework.CIS_V8, "4.7", "Manage default accounts"),
    (frozenset({"default", "credential"}), ComplianceFramework.CWE, "CWE-798", "Use of Hard-coded Credentials"),
    (frozenset({"hardcoded", "credential", "hard-coded"}), ComplianceFramework.CWE, "CWE-798", "Use of Hard-coded Credentials"),
    (frozenset({"unpatched", "outdated"}), ComplianceFramework.OWASP_TOP_10, "A06", "Vulnerable and Outdated Components"),
    (frozenset({"unpatched", "outdated"}), ComplianceFramework.CIS_V8, "7.4", "Automated vulnerability scans"),
    (frozenset({"unpatched", "outdated"}), ComplianceFramework.ISO_27001, "A.8.8", "Management of technical vulnerabilities"),
    (frozenset({"old", "version"}), ComplianceFramework.OWASP_TOP_10, "A06", "Vulnerable and Outdated Components"),
    (frozenset({"old", "version"}), ComplianceFramework.CIS_V8, "7.4", "Automated vulnerability scans"),
    (frozenset({"ssl", "weak", "encryption"}), ComplianceFramework.OWASP_TOP_10, "A02", "Cryptographic Failures"),
    (frozenset({"tls", "weak", "encryption"}), ComplianceFramework.OWASP_TOP_10, "A02", "Cryptographic Failures"),
    (frozenset({"ssl", "certificate"}), ComplianceFramework.OWASP_TOP_10, "A02", "Cryptographic Failures"),
    (frozenset({"ssl", "weak", "encryption"}), ComplianceFramework.CWE, "CWE-326", "Inadequate Encryption Strength"),
    (frozenset({"tls", "weak", "encryption"}), ComplianceFramework.CWE, "CWE-326", "Inadequate Encryption Strength"),
    (frozenset({"ssl", "tls", "encryption"}), ComplianceFramework.CIS_V8, "3.3", "Encrypt data in transit"),
    (frozenset({"ssl", "tls", "encryption"}), ComplianceFramework.NIST_CSF_2, "PR.DS-2", "Data-in-transit is protected"),
    (frozenset({"ssl", "tls", "encryption"}), ComplianceFramework.PCI_DSS_4, "4.1", "Encrypt cardholder data in transit"),
    (frozenset({"sensitive", "information"}), ComplianceFramework.OWASP_TOP_10, "A01", "Broken Access Control"),
    (frozenset({"information", "disclosure"}), ComplianceFramework.CWE, "CWE-200", "Information Exposure"),
    (frozenset({"sensitive", "information"}), ComplianceFramework.CWE, "CWE-200", "Information Exposure"),
    (frozenset({"sensitive", "information", "data", "leak"}), ComplianceFramework.NIST_CSF_2, "PR.DS-5", "Protections against data leaks"),
    (frozenset({"sensitive", "information", "data", "leak"}), ComplianceFramework.ISO_27001, "A.8.12", "Data leakage prevention"),
    (frozenset({"open", "port", "exposed", "service"}), ComplianceFramework.CIS_V8, "4.4", "Manage firewall on servers"),
    (frozenset({"open", "port", "exposed", "service"}), ComplianceFramework.NIST_CSF_2, "PR.PT-3", "Least functionality"),
    (frozenset({"open", "port", "exposed", "service"}), ComplianceFramework.MITRE_ATT_CK, "T1046", "Network Service Discovery"),
    (frozenset({"csrf", "cross", "site", "request", "forgery"}), ComplianceFramework.OWASP_TOP_10, "A01", "Broken Access Control"),
    (frozenset({"csrf", "cross", "site", "request", "forgery"}), ComplianceFramework.CWE, "CWE-352", "Cross-Site Request Forgery"),
    (frozenset({"command", "injection", "rce", "remote", "code"}), ComplianceFramework.OWASP_TOP_10, "A03", "Injection"),
    (frozenset({"command", "injection", "rce"}), ComplianceFramework.CWE, "CWE-78", "OS Command Injection"),
    (frozenset({"command", "injection", "rce"}), ComplianceFramework.MITRE_ATT_CK, "T1190", "Exploit Public-Facing Application"),
    (frozenset({"mfa", "multi", "factor", "two"}), ComplianceFramework.CIS_V8, "6.3", "Require MFA for administrative access"),
    (frozenset({"mfa", "multi", "factor", "two"}), ComplianceFramework.PCI_DSS_4, "8.4", "MFA implementation"),
    (frozenset({"mfa", "multi", "factor", "two"}), ComplianceFramework.NIST_CSF_2, "PR.AC-7", "User and device authentication"),
    (frozenset({"logging", "monitoring", "audit"}), ComplianceFramework.OWASP_TOP_10, "A09", "Security Logging and Monitoring Failures"),
    (frozenset({"logging", "monitoring"}), ComplianceFramework.CIS_V8, "8.2", "Collect audit logs"),
    (frozenset({"event", "monitoring", "logging"}), ComplianceFramework.NIST_CSF_2, "DE.AE-3", "Event data correlation"),
    (frozenset({"logging", "audit", "log"}), ComplianceFramework.PCI_DSS_4, "10.1", "Logging mechanisms"),
    (frozenset({"ssrf", "server", "side", "request", "forgery"}), ComplianceFramework.OWASP_TOP_10, "A10", "Server-Side Request Forgery"),
    (frozenset({"ssrf", "server", "side", "request"}), ComplianceFramework.CWE, "CWE-918", "Server-Side Request Forgery"),
    (frozenset({"path", "traversal", "directory", "listing"}), ComplianceFramework.CWE, "CWE-22", "Path Traversal"),
    (frozenset({"deserialization", "unsafe", "deserialize"}), ComplianceFramework.CWE, "CWE-502", "Deserialization of Untrusted Data"),
    (frozenset({"buffer", "overflow", "overrun"}), ComplianceFramework.CWE, "CWE-120", "Buffer Overflow"),
    (frozenset({"privilege", "escalation"}), ComplianceFramework.MITRE_ATT_CK, "T1068", "Exploitation for Privilege Escalation"),
    (frozenset({"phishing", "social", "engineering"}), ComplianceFramework.MITRE_ATT_CK, "T1566", "Phishing"),
    (frozenset({"phishing", "social", "engineering"}), ComplianceFramework.CIS_V8, "12.2", "Security awareness training"),
    (frozenset({"backup", "recovery", "disaster", "restore"}), ComplianceFramework.CIS_V8, "10.2", "Automated backups"),
    (frozenset({"backup", "recovery", "disaster"}), ComplianceFramework.NIST_CSF_2, "PR.IP-4", "Backups are conducted"),
    (frozenset({"backup", "recovery", "disaster"}), ComplianceFramework.ISO_27001, "A.8.13", "Backup of information"),
    (frozenset({"secure", "coding", "code", "review"}), ComplianceFramework.CIS_V8, "16.3", "Perform code review"),
    (frozenset({"secure", "coding", "code", "review"}), ComplianceFramework.ISO_27001, "A.8.28", "Secure coding"),
    (frozenset({"cve", "known", "vulnerability"}), ComplianceFramework.OWASP_TOP_10, "A06", "Vulnerable and Outdated Components"),
    (frozenset({"cve", "known", "vulnerability"}), ComplianceFramework.CIS_V8, "7.1", "Vulnerability management process"),
    (frozenset({"cve", "known", "vulnerability"}), ComplianceFramework.MITRE_ATT_CK, "T1190", "Exploit Public-Facing Application"),
    (frozenset({"cve", "known", "vulnerability"}), ComplianceFramework.NIST_CSF_2, "ID.RA-1", "Asset vulnerabilities identified"),
    (frozenset({"missing", "authentication", "no", "auth"}), ComplianceFramework.CWE, "CWE-306", "Missing Authentication"),
    (frozenset({"missing", "authentication", "no", "auth"}), ComplianceFramework.OWASP_TOP_10, "A07", "Authentication Failures"),
    (frozenset({"missing", "authentication", "no", "auth"}), ComplianceFramework.CIS_V8, "5.1", "Account inventory"),
]


class ComplianceMapper:
    """Maps findings to framework controls based on keyword analysis."""

    def map_finding(self, finding: Finding) -> list[FrameworkControl]:
        text = (finding.title + " " + finding.description).lower()
        words = frozenset(re.split(r"[\s\-_]+", text))
        matched: list[FrameworkControl] = []
        seen: set[tuple[str, str]] = set()

        for keywords, framework, ctrl_id, _ in _KEYWORD_CONTROL_MAP:
            if keywords.issubset(words):
                key = (framework.value, ctrl_id)
                if key not in seen:
                    seen.add(key)
                    defs = FRAMEWORK_DEFINITIONS.get(framework, ())
                    matched_ctrl = None
                    for dc in defs:
                        if dc.control_id.value == ctrl_id:
                            matched_ctrl = dc
                            break
                    if matched_ctrl is not None:
                        matched.append(matched_ctrl)
                    else:
                        matched.append(
                            FrameworkControl(
                                framework=framework,
                                control_id=ControlId(ctrl_id),
                                title=ctrl_id,
                                description="",
                            )
                        )
        return matched

    def map_all(self, findings: Sequence[Finding]) -> list[FindingControlMapping]:
        return [
            FindingControlMapping(
                finding_id=str(f.id),
                finding_title=f.title,
                severity=f.severity.label,
                controls=tuple(self.map_finding(f)),
            )
            for f in findings
        ]

    def get_framework_controls(self, framework: ComplianceFramework) -> tuple[FrameworkControl, ...]:
        return FRAMEWORK_DEFINITIONS.get(framework, ())
