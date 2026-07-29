from __future__ import annotations

from typing import Any

from kingsec.application.threat_intelligence.ports import EpssProviderPort
from kingsec.domain.threat_intelligence import EpssData


class EpssApiProvider(EpssProviderPort):
    BASE_URL = "https://api.first.org/data/v1/epss"

    def __init__(self, session: Any | None = None) -> None:
        self._session = session

    async def fetch_score(self, cve_code: str) -> EpssData | None:
        import httpx
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.BASE_URL}?cve={cve_code}",
                    timeout=30,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    epss_data = self._parse_response(data)
                    return epss_data.get(cve_code.upper())
                return None
        except Exception:
            return None

    async def fetch_bulk(self, cve_codes: list[str]) -> dict[str, EpssData]:
        import httpx
        if not cve_codes:
            return {}
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self.BASE_URL}?cve={','.join(cve_codes)}",
                    timeout=30,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return self._parse_response(data)
                return {}
        except Exception:
            return {}

    def _parse_response(self, data: dict[str, Any]) -> dict[str, EpssData]:
        results: dict[str, EpssData] = {}
        for item in data.get("data", []):
            cve_id = item.get("cve", "")
            epss = item.get("epss", {})
            if cve_id:
                results[cve_id] = EpssData(
                    score=float(epss.get("score", 0)),
                    percentile=float(epss.get("percentile", 0)),
                    model_version=data.get("meta", {}).get("model_version", ""),
                    date=item.get("date", ""),
                )
        return results
