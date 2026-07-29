from __future__ import annotations

import httpx
from typing import Any

from kingsec.application.threat_intelligence.ports import NvdProviderPort


class NvdApiProvider(NvdProviderPort):
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str | None = None, session: Any | None = None) -> None:
        self._api_key = api_key
        self._session = session

    async def fetch_cve(self, cve_code: str) -> dict[str, Any] | None:
        import httpx
        try:
            headers = {"apiKey": self._api_key} if self._api_key else {}
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.BASE_URL}?cveId={cve_code}",
                    headers=headers,
                    timeout=30,
                )
                if resp.status_code == 200:
                    data: dict[str, Any] = resp.json()
                    return self._parse_nvd_response(data)
                return None
        except Exception:
            return None

    async def fetch_recent(self, days: int = 7) -> list[dict[str, Any]]:
        from datetime import UTC, datetime, timedelta
        try:
            pub_start = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
            headers = {"apiKey": self._api_key} if self._api_key else {}
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.BASE_URL}?pubStartDate={pub_start}&resultsPerPage=50",
                    headers=headers,
                    timeout=30,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    return [self._parse_nvd_response({"vulnerabilities": [v]}) for v in vulnerabilities]
                return []
        except Exception:
            return []

    async def search(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        try:
            headers = {"apiKey": self._api_key} if self._api_key else {}
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.BASE_URL}?keywordSearch={query}&resultsPerPage={limit}",
                    headers=headers,
                    timeout=30,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    return [self._parse_nvd_response({"vulnerabilities": [v]}) for v in vulnerabilities]
                return []
        except Exception:
            return []

    def _parse_nvd_response(self, data: dict[str, Any]) -> dict[str, Any]:
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return data
        vuln = vulns[0]
        cve = vuln.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
        cvss_v30 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV30") else {}
        cvss = cvss_v31 or cvss_v30

        descriptions = cve.get("descriptions", [])
        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        refs = []
        for r in cve.get("references", []):
            refs.append({"url": r.get("url", ""), "source": r.get("source", ""), "tags": r.get("tags", [])})

        weaknesses = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("value"):
                    weaknesses.append(d["value"])

        return {
            "id": cve.get("id", ""),
            "description": description,
            "published": cve.get("published", ""),
            "lastModified": cve.get("lastModified", ""),
            "cvss": {
                "version": cvss.get("version", "3.1"),
                "vectorString": cvss.get("vectorString", ""),
                "baseScore": cvss.get("baseScore", 0),
                "baseSeverity": cvss.get("baseSeverity", "NONE"),
                "exploitabilityScore": cvss.get("exploitabilityScore", 0),
                "impactScore": cvss.get("impactScore", 0),
                "attackVector": cvss.get("attackVector", ""),
                "attackComplexity": cvss.get("attackComplexity", ""),
                "privilegesRequired": cvss.get("privilegesRequired", ""),
                "userInteraction": cvss.get("userInteraction", ""),
                "confidentialityImpact": cvss.get("confidentialityImpact", ""),
                "integrityImpact": cvss.get("integrityImpact", ""),
                "availabilityImpact": cvss.get("availabilityImpact", ""),
            },
            "references": refs,
            "weaknesses": weaknesses,
        }
