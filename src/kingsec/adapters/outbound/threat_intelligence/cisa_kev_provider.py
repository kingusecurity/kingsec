from __future__ import annotations

from typing import Any

from kingsec.application.threat_intelligence.ports import KevProviderPort


class CisaKevApiProvider(KevProviderPort):
    BASE_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, session: Any | None = None) -> None:
        self._session = session

    async def _fetch_raw(self) -> dict[str, Any]:
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.get(self.BASE_URL, timeout=30)
            if resp.status_code == 200:
                data: dict[str, Any] = resp.json()
                return data
            return {"vulnerabilities": []}

    async def fetch_all(self) -> list[dict[str, Any]]:
        data = await self._fetch_raw()
        return [self._normalize(v) for v in data.get("vulnerabilities", [])]

    async def fetch_recent(self, days: int = 7) -> list[dict[str, Any]]:
        from datetime import UTC, datetime, timedelta
        data = await self._fetch_raw()
        cutoff = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%d")
        results = []
        for v in data.get("vulnerabilities", []):
            date_added = v.get("dateAdded", "")
            if date_added >= cutoff:
                results.append(self._normalize(v))
        return results

    async def fetch_by_cve(self, cve_code: str) -> dict[str, Any] | None:
        data = await self._fetch_raw()
        for v in data.get("vulnerabilities", []):
            if v.get("cveID", "").upper() == cve_code.upper():
                return self._normalize(v)
        return None

    def _normalize(self, v: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": v.get("cveID", ""),
            "cve_id": v.get("cveID", ""),
            "vendor_project": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "vulnerability_name": v.get("vulnerabilityName", ""),
            "date_added": v.get("dateAdded", ""),
            "due_date": v.get("dueDate", ""),
            "required_action": v.get("requiredAction", ""),
            "known_ransomware_campaign_use": v.get("knownRansomwareCampaignUse", False),
            "notes": v.get("notes", ""),
        }
