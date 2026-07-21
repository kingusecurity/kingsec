"""Finding Enrichment Engine.

Offline, deterministic enrichment of correlated findings using only
information already present in the finding data. No external services,
databases, or network access — pure inference from text.

Design principles:
    * Immutable value objects (frozen dataclasses).
    * Pure functions — no side effects, no mutation.
    * Deterministic and stable output.
    * No infrastructure, plugin, or scanner imports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from kingsec.domain import Severity

if TYPE_CHECKING:
    from kingsec.application.correlation import CorrelatedFinding


# ---------------------------------------------------------------------------
# Constants — detection maps (heuristic, offline, deterministic)
# ---------------------------------------------------------------------------

_SERVICE_MAP: dict[str, str] = {
    "openssh": "SSH",
    "ssh": "SSH",
    "apache": "HTTP",
    "httpd": "HTTP",
    "nginx": "HTTP",
    "iis": "HTTP",
    "tomcat": "HTTP",
    "jetty": "HTTP",
    "mysql": "MySQL",
    "mariadb": "MySQL",
    "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL",
    "oracle": "Oracle Database",
    "redis": "Redis",
    "mongodb": "MongoDB",
    "elasticsearch": "Elasticsearch",
    "docker": "Docker",
    "kubernetes": "Kubernetes",
    "k8s": "Kubernetes",
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "jenkins": "Jenkins",
    "jira": "Jira",
    "confluence": "Confluence",
    "git": "Git",
    "ssl": "SSL/TLS",
    "tls": "SSL/TLS",
    "ftp": "FTP",
    "smtp": "SMTP",
    "dns": "DNS",
    "dhcp": "DHCP",
    "snmp": "SNMP",
    "ldap": "LDAP",
    "kerberos": "Kerberos",
    "rdp": "RDP",
    "vnc": "VNC",
    "telnet": "Telnet",
}

_TECHNOLOGY_MAP: dict[str, str] = {
    "apache": "Apache HTTP Server",
    "httpd": "Apache HTTP Server",
    "nginx": "Nginx",
    "iis": "Microsoft IIS",
    "tomcat": "Apache Tomcat",
    "jetty": "Eclipse Jetty",
    "jboss": "JBoss/WildFly",
    "wildfly": "JBoss/WildFly",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL",
    "oracle": "Oracle Database",
    "redis": "Redis",
    "mongodb": "MongoDB",
    "elasticsearch": "Elasticsearch",
    "docker": "Docker",
    "kubernetes": "Kubernetes",
    "k8s": "Kubernetes",
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "php": "PHP",
    "python": "Python",
    "node": "Node.js",
    "express": "Express.js",
    "jenkins": "Jenkins",
    "jira": "Jira",
    "confluence": "Confluence",
    "git": "Git",
    "openssl": "OpenSSL",
    "ruby": "Ruby",
    "rails": "Ruby on Rails",
    "django": "Django",
    "flask": "Flask",
    "spring": "Spring Framework",
    "struts": "Apache Struts",
    "hadoop": "Apache Hadoop",
    "spark": "Apache Spark",
    "kafka": "Apache Kafka",
    "rabbitmq": "RabbitMQ",
    "haproxy": "HAProxy",
    "memcached": "Memcached",
    "cassandra": "Apache Cassandra",
    "couchdb": "CouchDB",
    "neo4j": "Neo4j",
}

_PROTOCOL_MAP: dict[str, str] = {
    "ssh": "TCP",
    "openssh": "TCP",
    "http": "TCP",
    "https": "TCP",
    "mysql": "TCP",
    "postgresql": "TCP",
    "redis": "TCP",
    "mongodb": "TCP",
    "dns": "UDP",
    "dhcp": "UDP",
    "ntp": "UDP",
    "snmp": "UDP",
    "ftp": "TCP",
    "smtp": "TCP",
    "telnet": "TCP",
    "ldap": "TCP",
    "kerberos": "TCP/UDP",
    "rdp": "TCP",
    "vnc": "TCP",
}

_DEFAULT_PORT_MAP: dict[str, int] = {
    "https": 443,
    "http": 80,
    "ssh": 22,
    "openssh": 22,
    "apache": 80,
    "httpd": 80,
    "nginx": 80,
    "iis": 80,
    "tomcat": 8080,
    "mysql": 3306,
    "postgresql": 5432,
    "postgres": 5432,
    "redis": 6379,
    "mongodb": 27017,
    "elasticsearch": 9200,
    "docker": 2375,
    "kubernetes": 6443,
    "dns": 53,
    "dhcp": 67,
    "ntp": 123,
    "snmp": 161,
    "ftp": 21,
    "smtp": 25,
    "telnet": 23,
    "ldap": 389,
    "rdp": 3389,
    "vnc": 5900,
}

_OS_MAP: dict[str, str] = {
    "windows": "Microsoft Windows",
    "win32": "Microsoft Windows",
    "win64": "Microsoft Windows",
    "ubuntu": "Ubuntu Linux",
    "debian": "Debian Linux",
    "centos": "CentOS Linux",
    "red hat": "Red Hat Enterprise Linux",
    "rhel": "Red Hat Enterprise Linux",
    "fedora": "Fedora Linux",
    "linux": "Linux",
    "unix": "Unix",
    "macos": "macOS",
    "darwin": "macOS",
    "android": "Android",
    "ios": "iOS",
    "alpine": "Alpine Linux",
    "suse": "SUSE Linux",
    "opensuse": "openSUSE",
    "freebsd": "FreeBSD",
    "openbsd": "OpenBSD",
    "netbsd": "NetBSD",
    "solaris": "Solaris",
    "aix": "IBM AIX",
    "hp-ux": "HP-UX",
}

_BUSINESS_IMPACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"admin|administrator|admin panel|admin login|admin console", re.IGNORECASE), "High"),
    (re.compile(r"database|db |sql|mysql|postgres|oracle|redis|mongodb|cassandra", re.IGNORECASE), "Critical"),
    (re.compile(r"ssh|remote access|shell|rce|remote code|code execution|remote exec", re.IGNORECASE), "Critical"),
    (
        re.compile(
            r"auth.?bypass|authentication.?bypass|bypass.?auth|unauthorized|privilege.?escalation", re.IGNORECASE
        ),
        "Critical",
    ),
    (re.compile(r"sensitive|credential|password|secret|api.?key|token|pii|personal", re.IGNORECASE), "High"),
    (re.compile(r"injection|xss|sqli|rce|code.?exec|remote.?exec|command.?inject", re.IGNORECASE), "Critical"),
    (re.compile(r"directory.?traversal|path.?traversal|lfi|rfi|file.?inclusion", re.IGNORECASE), "High"),
    (re.compile(r"misconfig|open bucket|exposed|information.?disclosure|leak", re.IGNORECASE), "Medium"),
    (re.compile(r"web|http|server|public|https?://", re.IGNORECASE), "Medium"),
    (re.compile(r"missing header|csp|hsts|x.?frame|content.?type|xss.?protect", re.IGNORECASE), "Low"),
    (re.compile(r"discovery|subdomain|dns|enumeration|banner|fingerprint", re.IGNORECASE), "Low"),
]

_REMEDIATION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"missing header|csp|hsts|x.?frame|x.?content|x.?permitted|add header|set header|configure header",
            re.IGNORECASE,
        ),
        "Easy",
    ),
    (re.compile(r"upgrade|update|patch|version|outdated|deprecated|newer|old.?version|bump", re.IGNORECASE), "Medium"),
    (re.compile(r"reconfigur|migrate|redeploy|infrastructure|architecture|redesign|refactor", re.IGNORECASE), "Hard"),
    (re.compile(r"ssl.?cert|tls.?cert|certificate|expired|renew", re.IGNORECASE), "Medium"),
    (re.compile(r"firewall|network.?change|dns.?change|load.?balancer|vpc|subnet|acl", re.IGNORECASE), "Hard"),
    (re.compile(r"input.?valid|sanitize|escape|encode|filter", re.IGNORECASE), "Medium"),
    (re.compile(r"remove|disable|turn.?off|deprecat|delete|drop", re.IGNORECASE), "Easy"),
]

_ATTACK_SURFACE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"web|http|apache|nginx|iis|tomcat|wordpress|drupal|joomla|php|node|express|django|flask|rails|xss|sqli|header|csp|hsts",
            re.IGNORECASE,
        ),
        "Web Application",
    ),
    (re.compile(r"ssh|openssh|remote|telnet|ftp|smtp|rdp|vnc|snmp", re.IGNORECASE), "Network Service"),
    (
        re.compile(r"database|sql|mysql|postgres|oracle|redis|mongodb|mariadb|cassandra|elasticsearch", re.IGNORECASE),
        "Database",
    ),
    (re.compile(r"dns|domain|subdomain|zone", re.IGNORECASE), "DNS"),
    (re.compile(r"api|rest|graphql|soap|restful|endpoint", re.IGNORECASE), "API"),
    (re.compile(r"container|docker|kubernetes|k8s|pod|image|registry", re.IGNORECASE), "Container"),
    (re.compile(r"cloud|aws|s3|ec2|lambda|azure|gcp|cloudfront|route53", re.IGNORECASE), "Cloud"),
    (re.compile(r"file|directory|path|local|filesystem|storage|disk", re.IGNORECASE), "File System"),
    (re.compile(r"auth|login|sso|oauth|saml|openid|identity", re.IGNORECASE), "Authentication"),
    (re.compile(r"network|port|firewall|vpn|gateway|router|switch", re.IGNORECASE), "Network Infrastructure"),
]

_RISK_FACTOR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"remote|network.?accessible|externally.?accessible|public", re.IGNORECASE), "Remote Exploitable"),
    (re.compile(r"auth.?bypass|authentication.?bypass|no.?auth|without.?auth", re.IGNORECASE), "Authentication Bypass"),
    (
        re.compile(r"credential|password|secret|api.?key|token|plain.?text|cleartext", re.IGNORECASE),
        "Credential Exposure",
    ),
    (
        re.compile(r"rce|code.?execution|remote.?code|shell|command.?inject|arbitrary.?code", re.IGNORECASE),
        "Remote Code Execution",
    ),
    (
        re.compile(r"xss|cross.?site.?script|inject|sqli|sql.?inject|ldap.?inject|command.?inject", re.IGNORECASE),
        "Injection",
    ),
    (re.compile(r"dos|ddos|denial.?of.?service|crash|hang|exhaust", re.IGNORECASE), "Denial of Service"),
    (re.compile(r"privilege.?escalation|privesc|elevat|root|admin.?access", re.IGNORECASE), "Privilege Escalation"),
    (re.compile(r"information.?disclosure|info.?leak|expos|sensitive.?data", re.IGNORECASE), "Information Disclosure"),
    (
        re.compile(r"misconfig|insecure.?config|default.?config|default.?credential|default.?password", re.IGNORECASE),
        "Misconfiguration",
    ),
]

_PORT_RE = re.compile(r"(?:port\s*[:#]?\s*|:)(\d{1,5})", re.IGNORECASE)

_SOFTWARE_NAMES: frozenset[str] = frozenset(
    {
        "openssh",
        "ssh",
        "apache",
        "httpd",
        "nginx",
        "iis",
        "mysql",
        "mariadb",
        "postgresql",
        "postgres",
        "oracle",
        "redis",
        "mongodb",
        "elasticsearch",
        "tomcat",
        "jetty",
        "jboss",
        "wildfly",
        "php",
        "python",
        "node",
        "express",
        "wordpress",
        "drupal",
        "joomla",
        "openssl",
        "ssl",
        "tls",
        "docker",
        "kubernetes",
        "k8s",
        "git",
        "jenkins",
        "jira",
        "confluence",
        "ftp",
        "smtp",
        "dns",
        "dhcp",
        "ntp",
        "snmp",
        "ldap",
        "kerberos",
        "rdp",
        "vnc",
        "telnet",
        "ruby",
        "rails",
        "django",
        "flask",
        "spring",
        "struts",
        "hadoop",
        "spark",
        "kafka",
        "rabbitmq",
        "haproxy",
        "memcached",
        "cassandra",
        "couchdb",
        "neo4j",
    }
)

_SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 30,
    Severity.MEDIUM: 20,
    Severity.LOW: 10,
    Severity.INFORMATIONAL: 0,
}

_BUSINESS_IMPACT_WEIGHT: dict[str, int] = {
    "Critical": 20,
    "High": 15,
    "Medium": 10,
    "Low": 5,
}

_EXPLOIT_LIKELIHOOD_WEIGHT: dict[str, int] = {
    "High": 10,
    "Medium": 6,
    "Low": 3,
}

_PRIORITY_THRESHOLDS: list[tuple[int, str]] = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_combined_text(finding: CorrelatedFinding) -> str:
    """Build a single searchable text blob from all finding content."""
    parts: list[str] = [finding.title, finding.description]
    parts.extend(finding.tags)
    for nf in finding.merged_findings:
        parts.append(nf.title)
        parts.append(nf.description)
        parts.extend(nf.tags)
    return " ".join(parts)


def _extract_software_names(text: str) -> tuple[str, ...]:
    """Extract known software names from text, preserving insertion order."""
    lower = text.lower()
    seen: set[str] = set()
    result: list[str] = []
    for sw in _SOFTWARE_NAMES:
        if sw in lower and sw not in seen:
            seen.add(sw)
            result.append(sw)
    return tuple(result)


def _extract_port_from_text(text: str) -> int | None:
    """Extract the first valid port number from text."""
    for match in _PORT_RE.finditer(text):
        port = int(match.group(1))
        if 1 <= port <= 65535:
            return port
    return None


# ---------------------------------------------------------------------------
# Value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnrichedFinding:
    """An enriched finding with additional security intelligence.

    All enrichment is performed offline using only the information
    already present in the original ``CorrelatedFinding``.
    """

    correlation_id: str
    title: str
    description: str
    severity: Severity
    category: str
    confidence: float
    scanner_sources: tuple[str, ...]
    affected_assets: tuple[str, ...]
    references: tuple[str, ...]
    recommendations: tuple[str, ...]
    tags: tuple[str, ...]
    software: tuple[str, ...]
    service: str | None
    protocol: str | None
    port: int | None
    technology: tuple[str, ...]
    operating_system: str | None
    attack_surface: str | None
    risk_factors: tuple[str, ...]
    business_impact: str | None
    exploit_likelihood: str | None
    remediation_complexity: str | None
    priority: str
    metadata: dict[str, str]

    def __post_init__(self) -> None:
        if not self.correlation_id:
            raise ValueError("correlation_id must not be empty")
        if not self.title:
            raise ValueError("title must not be empty")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity enum")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")


# ---------------------------------------------------------------------------
# Enrichment Engine
# ---------------------------------------------------------------------------


class FindingEnricher:
    """Offline enrichment engine for correlated findings.

    Every method is deterministic, stateless, and purely derived from
    the text and metadata already present in the finding. No external
    services, databases, or network access are ever required.
    """

    def enrich(self, findings: list[CorrelatedFinding]) -> list[EnrichedFinding]:
        """Enrich a list of correlated findings.

        Args:
            findings: Correlated findings from the correlation engine.

        Returns:
            A list of ``EnrichedFinding`` objects, one per input.
        """
        if not findings:
            return []
        return [self.enrich_one(f) for f in findings]

    def enrich_one(self, finding: CorrelatedFinding) -> EnrichedFinding:
        """Enrich a single correlated finding into an ``EnrichedFinding``."""
        text = _extract_combined_text(finding)
        software = _extract_software_names(text)
        service = self.detect_service(finding)
        protocol = self.detect_protocol(finding)
        port = self.detect_port(finding)
        technology = self.detect_technology(finding)
        operating_system = self.detect_operating_system(finding)
        attack_surface = self._detect_attack_surface(text)
        risk_factors = self._detect_risk_factors(text)
        business_impact = self.estimate_business_impact(finding)
        exploit_likelihood = self.estimate_exploit_likelihood(finding)
        remediation_complexity = self.estimate_remediation_complexity(finding)
        priority = self.calculate_priority(finding)
        metadata = self._build_metadata(
            service,
            protocol,
            port,
            technology,
            operating_system,
            attack_surface,
        )

        return EnrichedFinding(
            correlation_id=finding.correlation_id,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            category=finding.category,
            confidence=finding.confidence,
            scanner_sources=finding.scanner_sources,
            affected_assets=finding.affected_assets,
            references=finding.references,
            recommendations=finding.recommendations,
            tags=finding.tags,
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
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Detection methods
    # ------------------------------------------------------------------

    def detect_service(self, finding: CorrelatedFinding) -> str | None:
        """Detect the network service from software names in the finding.

        Returns:
            The first matching service name, or ``None``.
        """
        text = _extract_combined_text(finding).lower()
        for sw, service in _SERVICE_MAP.items():
            if sw in text:
                return service
        return None

    def detect_technology(self, finding: CorrelatedFinding) -> tuple[str, ...]:
        """Detect technologies from software names in the finding.

        Returns:
            A tuple of detected technology names, deduplicated and in
            insertion order.
        """
        text = _extract_combined_text(finding).lower()
        seen: set[str] = set()
        result: list[str] = []
        for sw, tech in _TECHNOLOGY_MAP.items():
            if sw in text and tech not in seen:
                seen.add(tech)
                result.append(tech)
        return tuple(result)

    def detect_protocol(self, finding: CorrelatedFinding) -> str | None:
        """Detect the transport protocol from software names.

        Returns:
            The first matching protocol, or ``None``.
        """
        text = _extract_combined_text(finding).lower()
        for sw, protocol in _PROTOCOL_MAP.items():
            if sw in text:
                return protocol
        return None

    def detect_port(self, finding: CorrelatedFinding) -> int | None:
        """Detect the port number.

        First attempts to extract an explicit port from text (e.g.
        ``port 22`` or ``:443``), then falls back to the default port
        for any detected service.

        Returns:
            A port number, or ``None`` if undetectable.
        """
        text = _extract_combined_text(finding)
        port = _extract_port_from_text(text)
        if port is not None:
            return port
        lower = text.lower()
        for sw, default_port in _DEFAULT_PORT_MAP.items():
            if sw in lower:
                return default_port
        return None

    def detect_operating_system(self, finding: CorrelatedFinding) -> str | None:
        """Detect the operating system from keywords in the finding.

        Returns:
            The first matching OS name, or ``None``.
        """
        text = _extract_combined_text(finding).lower()
        for keyword, os_name in _OS_MAP.items():
            if keyword in text:
                return os_name
        return None

    # ------------------------------------------------------------------
    # Impact / likelihood / complexity estimation
    # ------------------------------------------------------------------

    def estimate_business_impact(self, finding: CorrelatedFinding) -> str | None:
        """Estimate the business impact based on keywords in the finding.

        Returns:
            ``Critical``, ``High``, ``Medium``, ``Low``, or ``None``.
        """
        text = _extract_combined_text(finding)
        for pattern, impact in _BUSINESS_IMPACT_PATTERNS:
            if pattern.search(text):
                return impact
        return None

    def estimate_exploit_likelihood(self, finding: CorrelatedFinding) -> str | None:
        """Estimate exploit likelihood based on severity and confidence.

        Rules::

            INFORMATIONAL                       → Low
            CRITICAL + confidence ≥ 0.6          → High
            CRITICAL + confidence < 0.6          → Medium
            HIGH + confidence ≥ 0.6               → High
            HIGH + confidence < 0.6               → Medium
            MEDIUM                                → Medium
            LOW                                  → Low
        """
        if finding.severity == Severity.INFORMATIONAL:
            return "Low"
        if finding.severity >= Severity.CRITICAL:
            return "High" if finding.confidence >= 0.6 else "Medium"
        if finding.severity >= Severity.HIGH:
            return "High" if finding.confidence >= 0.6 else "Medium"
        if finding.severity >= Severity.MEDIUM:
            return "Medium"
        return "Low"

    def estimate_remediation_complexity(self, finding: CorrelatedFinding) -> str | None:
        """Estimate remediation complexity based on keywords in the finding.

        Returns:
            ``Easy``, ``Medium``, ``Hard``, or ``None``.
        """
        text = _extract_combined_text(finding)
        for pattern, complexity in _REMEDIATION_PATTERNS:
            if pattern.search(text):
                return complexity
        return None

    # ------------------------------------------------------------------
    # Priority
    # ------------------------------------------------------------------

    def calculate_priority(self, finding: CorrelatedFinding) -> str:
        """Calculate the priority level.

        Formula::

            score = severity_weight + confidence_contribution
                    + business_impact_weight + exploit_likelihood_weight

        Thresholds::

            ≥ 80  → Critical
            ≥ 60  → High
            ≥ 40  → Medium
            < 40  → Low
        """
        score = _SEVERITY_WEIGHT.get(finding.severity, 0)
        score += int(finding.confidence * 30)

        impact = self.estimate_business_impact(finding)
        if impact is not None:
            score += _BUSINESS_IMPACT_WEIGHT.get(impact, 0)

        likelihood = self.estimate_exploit_likelihood(finding)
        if likelihood is not None:
            score += _EXPLOIT_LIKELIHOOD_WEIGHT.get(likelihood, 0)

        for threshold, label in _PRIORITY_THRESHOLDS:
            if score >= threshold:
                return label
        return "Low"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_attack_surface(text: str) -> str | None:
        """Detect the attack surface category from the finding text."""
        for pattern, surface in _ATTACK_SURFACE_PATTERNS:
            if pattern.search(text):
                return surface
        return None

    @staticmethod
    def _detect_risk_factors(text: str) -> tuple[str, ...]:
        """Detect risk factors from the finding text."""
        seen: set[str] = set()
        result: list[str] = []
        for pattern, risk in _RISK_FACTOR_PATTERNS:
            if pattern.search(text) and risk not in seen:
                seen.add(risk)
                result.append(risk)
        return tuple(result)

    @staticmethod
    def _build_metadata(
        service: str | None,
        protocol: str | None,
        port: int | None,
        technology: tuple[str, ...],
        operating_system: str | None,
        attack_surface: str | None,
    ) -> dict[str, str]:
        """Build the metadata dict from detected enrichment values."""
        meta: dict[str, str] = {}
        if service:
            meta["detected_service"] = service
        if protocol:
            meta["detected_protocol"] = protocol
        if port is not None:
            meta["detected_port"] = str(port)
        if technology:
            meta["detected_stack"] = ", ".join(technology)
        if operating_system:
            meta["detected_os"] = operating_system
        if attack_surface:
            meta["detected_attack_surface"] = attack_surface
        return meta
