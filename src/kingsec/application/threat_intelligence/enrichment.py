from __future__ import annotations

from typing import Any

from ...domain.threat_intelligence import (
    AttackComplexity,
    AttackVector,
    CiaImpact,
    CveEntry,
    CveReference,
    CvssData,
    EpssData,
    ExploitMaturity,
    KevEntry,
    PrivilegesRequired,
    UserInteraction,
)
from ...domain.identifiers import CveId
from .ports import EpssProviderPort, KevProviderPort, MitreCveProviderPort, NvdProviderPort


class CveEnrichmentService:
    def __init__(
        self,
        nvd_provider: NvdProviderPort | None = None,
        epss_provider: EpssProviderPort | None = None,
        kev_provider: KevProviderPort | None = None,
        mitre_provider: MitreCveProviderPort | None = None,
    ) -> None:
        self._nvd = nvd_provider
        self._epss = epss_provider
        self._kev = kev_provider
        self._mitre = mitre_provider

    async def enrich(self, cve_code: str) -> CveEntry | None:
        nvd_data = await self._fetch_nvd(cve_code) if self._nvd else None
        if not nvd_data:
            mitre_data = await self._fetch_mitre(cve_code) if self._mitre else None
            if not mitre_data:
                return None
            nvd_data = mitre_data

        epss_data = await self._fetch_epss(cve_code) if self._epss else None
        kev_data = await self._fetch_kev(cve_code) if self._kev else None

        entry = self._build_entry(nvd_data, epss_data, kev_data)
        entry.calculate_threat_score()
        return entry

    async def enrich_bulk(self, cve_codes: list[str]) -> list[CveEntry]:
        results: list[CveEntry] = []
        for code in cve_codes:
            entry = await self.enrich(code)
            if entry:
                results.append(entry)
        return results

    async def _fetch_nvd(self, cve_code: str) -> dict[str, Any] | None:
        if self._nvd is None:
            return None
        try:
            return await self._nvd.fetch_cve(cve_code)
        except Exception:
            return None

    async def _fetch_mitre(self, cve_code: str) -> dict[str, Any] | None:
        if self._mitre is None:
            return None
        try:
            return await self._mitre.fetch_cve(cve_code)
        except Exception:
            return None

    async def _fetch_epss(self, cve_code: str) -> EpssData | None:
        if self._epss is None:
            return None
        try:
            return await self._epss.fetch_score(cve_code)
        except Exception:
            return None

    async def _fetch_kev(self, cve_code: str) -> dict[str, Any] | None:
        if self._kev is None:
            return None
        try:
            return await self._kev.fetch_by_cve(cve_code)
        except Exception:
            return None

    def _build_entry(
        self,
        data: dict[str, Any],
        epss_data: EpssData | None = None,
        kev_data: dict[str, Any] | None = None,
    ) -> CveEntry:
        cvss = self._parse_cvss(data.get("cvss", {}))
        cve_code = data.get("id", data.get("cve_id", ""))
        return CveEntry(
            cve_id=CveId.generate(),
            cve_code=cve_code,
            description=data.get("description", ""),
            severity=cvss.base_severity,
            published_date=data.get("published", data.get("published_date")),
            last_modified=data.get("lastModified", data.get("last_modified")),
            cvss_data=cvss,
            epss_data=epss_data,
            exploit_maturity=self._parse_maturity(data.get("exploit_maturity", "")),
            affected_products=self._parse_products(data.get("affected_products", [])),
            references=self._parse_references(data.get("references", [])),
            vendor_advisories=data.get("vendor_advisories", []),
            weaknesses=data.get("weaknesses", []),
            is_kev=kev_data is not None,
            kev_entry=self._build_kev(kev_data) if kev_data else None,
        )

    def _parse_cvss(self, data: dict[str, Any]) -> CvssData:
        return CvssData(
            version=data.get("version", "3.1"),
            vector_string=data.get("vectorString", ""),
            base_score=float(data.get("baseScore", 0)),
            base_severity=data.get("baseSeverity", "NONE"),
            exploitability_score=float(data.get("exploitabilityScore", 0)),
            impact_score=float(data.get("impactScore", 0)),
            attack_vector=AttackVector(data["attackVector"].lower()) if data.get("attackVector") else None,
            attack_complexity=AttackComplexity(data["attackComplexity"].lower()) if data.get("attackComplexity") else None,
            privileges_required=PrivilegesRequired(data["privilegesRequired"].lower()) if data.get("privilegesRequired") else None,
            user_interaction=UserInteraction(data["userInteraction"].lower()) if data.get("userInteraction") else None,
            confidentiality_impact=CiaImpact(data["confidentialityImpact"].lower()) if data.get("confidentialityImpact") else None,
            integrity_impact=CiaImpact(data["integrityImpact"].lower()) if data.get("integrityImpact") else None,
            availability_impact=CiaImpact(data["availabilityImpact"].lower()) if data.get("availabilityImpact") else None,
        )

    def _parse_maturity(self, value: str) -> ExploitMaturity:
        try:
            return ExploitMaturity(value)
        except ValueError:
            return ExploitMaturity.UNKNOWN

    def _parse_products(self, products: list[dict[str, Any]]) -> list[Any]:
        from ...domain.threat_intelligence import AffectedProduct
        return [AffectedProduct(**p) for p in products if isinstance(p, dict)]

    def _parse_references(self, refs: list[Any]) -> list[CveReference]:
        result: list[CveReference] = []
        for r in refs:
            if isinstance(r, dict):
                result.append(CveReference(url=r.get("url", ""), source=r.get("source", ""), tags=tuple(r.get("tags", []))))
            elif isinstance(r, str):
                result.append(CveReference(url=r))
        return result

    def _build_kev(self, data: dict[str, Any]) -> KevEntry:
        return KevEntry(
            id=data.get("id", ""),
            cve_id=data.get("cve_id", data.get("cveID", "")),
            vendor_project=data.get("vendorProject", data.get("vendor_project", "")),
            product=data.get("product", ""),
            vulnerability_name=data.get("vulnerabilityName", data.get("vulnerability_name", "")),
            date_added=data.get("dateAdded", data.get("date_added", "")),
            due_date=data.get("dueDate", data.get("due_date", "")),
            required_action=data.get("requiredAction", data.get("required_action", "")),
            known_ransomware_campaign_use=bool(data.get("knownRansomwareCampaignUse", data.get("known_ransomware_campaign_use", False))),
            notes=data.get("notes", ""),
            cve_title=data.get("cve_title", ""),
        )


class EpssService:
    def __init__(self, epss_provider: EpssProviderPort | None = None) -> None:
        self._provider = epss_provider

    async def get_score(self, cve_code: str) -> EpssData | None:
        if not self._provider:
            return None
        try:
            return await self._provider.fetch_score(cve_code)
        except Exception:
            return None

    async def get_bulk_scores(self, cve_codes: list[str]) -> dict[str, EpssData]:
        if not self._provider or not cve_codes:
            return {}
        try:
            return await self._provider.fetch_bulk(cve_codes)
        except Exception:
            return {}


class KevService:
    def __init__(self, kev_provider: KevProviderPort | None = None) -> None:
        self._provider = kev_provider

    async def fetch_all(self) -> list[dict[str, Any]]:
        if not self._provider:
            return []
        try:
            return await self._provider.fetch_all()
        except Exception:
            return []

    async def fetch_recent(self, days: int = 7) -> list[dict[str, Any]]:
        if not self._provider:
            return []
        try:
            return await self._provider.fetch_recent(days)
        except Exception:
            return []

    async def fetch_by_cve(self, cve_code: str) -> dict[str, Any] | None:
        if not self._provider:
            return None
        try:
            return await self._provider.fetch_by_cve(cve_code)
        except Exception:
            return None


class CvssService:
    SEVERITY_MAP = {
        (9.0, 10.0): "CRITICAL",
        (7.0, 8.9): "HIGH",
        (4.0, 6.9): "MEDIUM",
        (0.1, 3.9): "LOW",
    }

    @classmethod
    def calculate_severity(cls, score: float) -> str:
        for (low, high), severity in cls.SEVERITY_MAP.items():
            if low <= score <= high:
                return severity
        return "NONE"

    @classmethod
    def calculate_impact_score(cls, cvss: CvssData) -> float:
        c = 0.0
        i = 0.0
        a = 0.0
        if cvss.confidentiality_impact:
            c = cls._impact_value(cvss.confidentiality_impact)
        if cvss.integrity_impact:
            i = cls._impact_value(cvss.integrity_impact)
        if cvss.availability_impact:
            a = cls._impact_value(cvss.availability_impact)
        return round(1 - ((1 - c) * (1 - i) * (1 - a)), 2)

    @classmethod
    def _impact_value(cls, impact: CiaImpact) -> float:
        return 0.0 if impact == CiaImpact.NONE else 0.275 if impact == CiaImpact.LOW else 0.66
