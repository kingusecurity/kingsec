from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .errors import InvariantViolation
from .identifiers import CveId, KevEntryId, ThreatFeedId


class ThreatFeedType(StrEnum):
    NVD = "nvd"
    CISA_KEV = "cisa_kev"
    EPSS = "epss"
    MITRE_CVE = "mitre_cve"
    FIRST_EPSS = "first_epss"
    VENDOR_ADVISORY = "vendor_advisory"
    CUSTOM = "custom"


class ExploitMaturity(StrEnum):
    UNKNOWN = "unknown"
    PROOF_OF_CONCEPT = "proof_of_concept"
    WEAPONIZED = "weaponized"
    ACTIVE_EXPLOITATION = "active_exploitation"
    NO_EXPLOIT = "no_exploit"


class AttackVector(StrEnum):
    NETWORK = "network"
    ADJACENT_NETWORK = "adjacent_network"
    LOCAL = "local"
    PHYSICAL = "physical"


class AttackComplexity(StrEnum):
    LOW = "low"
    HIGH = "high"


class PrivilegesRequired(StrEnum):
    NONE = "none"
    LOW = "low"
    HIGH = "high"


class UserInteraction(StrEnum):
    NONE = "none"
    REQUIRED = "required"


class CiaImpact(StrEnum):
    NONE = "none"
    LOW = "low"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class CvssData:
    version: str = "3.1"
    vector_string: str = ""
    base_score: float = 0.0
    base_severity: str = "NONE"
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    attack_vector: AttackVector | None = None
    attack_complexity: AttackComplexity | None = None
    privileges_required: PrivilegesRequired | None = None
    user_interaction: UserInteraction | None = None
    confidentiality_impact: CiaImpact | None = None
    integrity_impact: CiaImpact | None = None
    availability_impact: CiaImpact | None = None


@dataclass(frozen=True, slots=True)
class AffectedProduct:
    vendor: str = ""
    product: str = ""
    version: str = ""
    operator: str = ""


@dataclass(frozen=True, slots=True)
class CveReference:
    url: str = ""
    source: str = ""
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EpssData:
    score: float = 0.0
    percentile: float = 0.0
    model_version: str = ""
    date: str = ""


@dataclass(frozen=True, slots=True)
class KevEntry:
    id: str
    cve_id: str
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: str = ""
    due_date: str = ""
    required_action: str = ""
    known_ransomware_campaign_use: bool = False
    notes: str = ""
    cve_title: str = ""


class CveEntry:
    def __init__(
        self,
        cve_id: CveId,
        cve_code: str,
        *,
        description: str = "",
        severity: str = "NONE",
        published_date: str | None = None,
        last_modified: str | None = None,
        cvss_data: CvssData | None = None,
        epss_data: EpssData | None = None,
        exploit_maturity: ExploitMaturity = ExploitMaturity.UNKNOWN,
        affected_products: list[AffectedProduct] | None = None,
        references: list[CveReference] | None = None,
        vendor_advisories: list[str] | None = None,
        weaknesses: list[str] | None = None,
        is_kev: bool = False,
        kev_entry: KevEntry | None = None,
        threat_score: float = 0.0,
        exploitability_score: float = 0.0,
        priority_score: float = 0.0,
        metadata: dict[str, Any] | None = None,
        created_at: str | None = None,
        updated_at: str | None = None,
    ) -> None:
        if not isinstance(cve_id, CveId):
            raise InvariantViolation("cve_id must be a CveId")
        now = created_at or datetime.now(UTC).isoformat()
        self._id = cve_id
        self._cve_code = cve_code.upper().strip()
        self._description = description
        self._severity = severity
        self._published_date = published_date
        self._last_modified = last_modified
        self._cvss_data = cvss_data or CvssData()
        self._epss_data = epss_data
        self._exploit_maturity = exploit_maturity
        self._affected_products = list(affected_products) if affected_products else []
        self._references = list(references) if references else []
        self._vendor_advisories = list(vendor_advisories) if vendor_advisories else []
        self._weaknesses = list(weaknesses) if weaknesses else []
        self._is_kev = is_kev
        self._kev_entry = kev_entry
        self._threat_score = threat_score
        self._exploitability_score = exploitability_score
        self._priority_score = priority_score
        self._metadata = dict(metadata) if metadata else {}
        self._created_at = now
        self._updated_at = updated_at or now

    @classmethod
    def create(cls, cve_code: str, **kwargs: Any) -> CveEntry:
        return cls(CveId.generate(), cve_code, **kwargs)

    @property
    def id(self) -> CveId:
        return self._id

    @property
    def cve_code(self) -> str:
        return self._cve_code

    @property
    def description(self) -> str:
        return self._description

    @property
    def severity(self) -> str:
        return self._severity

    @property
    def published_date(self) -> str | None:
        return self._published_date

    @property
    def last_modified(self) -> str | None:
        return self._last_modified

    @property
    def cvss_data(self) -> CvssData:
        return self._cvss_data

    @property
    def epss_data(self) -> EpssData | None:
        return self._epss_data

    @property
    def exploit_maturity(self) -> ExploitMaturity:
        return self._exploit_maturity

    @property
    def affected_products(self) -> tuple[AffectedProduct, ...]:
        return tuple(self._affected_products)

    @property
    def references(self) -> tuple[CveReference, ...]:
        return tuple(self._references)

    @property
    def vendor_advisories(self) -> tuple[str, ...]:
        return tuple(self._vendor_advisories)

    @property
    def weaknesses(self) -> tuple[str, ...]:
        return tuple(self._weaknesses)

    @property
    def is_kev(self) -> bool:
        return self._is_kev

    @property
    def kev_entry(self) -> KevEntry | None:
        return self._kev_entry

    @property
    def threat_score(self) -> float:
        return self._threat_score

    @property
    def exploitability_score(self) -> float:
        return self._exploitability_score

    @property
    def priority_score(self) -> float:
        return self._priority_score

    @property
    def metadata(self) -> dict[str, Any]:
        return dict(self._metadata)

    @property
    def created_at(self) -> str:
        return self._created_at

    @property
    def updated_at(self) -> str:
        return self._updated_at

    def calculate_threat_score(self) -> float:
        cvss = self._cvss_data.base_score
        epss = self._epss_data.score if self._epss_data else 0.0
        kev_bonus = 10.0 if self._is_kev else 0.0
        maturity_weights = {
            ExploitMaturity.ACTIVE_EXPLOITATION: 10.0,
            ExploitMaturity.WEAPONIZED: 8.0,
            ExploitMaturity.PROOF_OF_CONCEPT: 5.0,
            ExploitMaturity.NO_EXPLOIT: 1.0,
            ExploitMaturity.UNKNOWN: 2.0,
        }
        maturity_score = maturity_weights.get(self._exploit_maturity, 2.0)
        self._threat_score = min(cvss + (epss * 100) + kev_bonus + maturity_score, 100.0)
        self._exploitability_score = self._cvss_data.exploitability_score + maturity_score
        self._priority_score = min((self._threat_score * 0.6) + (self._exploitability_score * 0.4), 100.0)
        return round(self._threat_score, 2)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CveEntry) and other._id == self._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return f"CveEntry(cve={self._cve_code!r}, score={self._threat_score})"


@dataclass(frozen=True, slots=True)
class ThreatFeedEntry:
    feed_id: str
    feed_type: ThreatFeedType
    title: str = ""
    description: str = ""
    source_url: str = ""
    entries: int = 0
    last_synced: str = ""
    status: str = "active"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ThreatIntelligenceSummary:
    total_cves: int = 0
    critical_cves: int = 0
    high_cves: int = 0
    medium_cves: int = 0
    low_cves: int = 0
    kev_count: int = 0
    active_exploitations: int = 0
    average_threat_score: float = 0.0
    average_epss_score: float = 0.0
    feeds_active: int = 0
    feeds_total: int = 0
    trending_threats: list[dict[str, Any]] = field(default_factory=list)
    top_critical_cves: list[dict[str, Any]] = field(default_factory=list)
    recent_kev_additions: int = 0


@dataclass(frozen=True, slots=True)
class ThreatTrendPoint:
    date: str
    new_cves: int = 0
    critical_cves: int = 0
    kev_additions: int = 0
    average_score: float = 0.0
