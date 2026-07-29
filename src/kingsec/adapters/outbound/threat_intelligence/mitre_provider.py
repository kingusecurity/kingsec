from __future__ import annotations

from typing import Any

from kingsec.application.threat_intelligence.ports import MitreCveProviderPort


class MitreCveProvider(MitreCveProviderPort):
    BASE_URL = "https://cveawg.mitre.org/api/cve"

    async def fetch_cve(self, cve_code: str) -> dict[str, Any] | None:
        import httpx
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{self.BASE_URL}/{cve_code}", timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    return self._parse_mitre_response(data, cve_code)
                return None
        except Exception:
            return None

    async def fetch_recent(self, days: int = 7) -> list[dict[str, Any]]:
        return []

    def _parse_mitre_response(self, data: dict[str, Any], cve_code: str) -> dict[str, Any]:
        containers = data.get("containers", {})
        cna = containers.get("cna", {})
        descriptions = cna.get("descriptions", [])
        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        refs = []
        for r in cna.get("references", []):
            refs.append({"url": r.get("url", ""), "source": "mitre", "tags": []})

        metrics = cna.get("metrics", [])
        cvss: dict[str, Any] = {}
        for m in metrics:
            cvss_data = m.get("cvssV3_1") or m.get("cvssV3_0") or {}
            if cvss_data:
                cvss = cvss_data
                break

        return {
            "id": cve_code,
            "description": description,
            "published": data.get("datePublished", ""),
            "lastModified": data.get("dateUpdated", ""),
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
            "weaknesses": [],
        }
