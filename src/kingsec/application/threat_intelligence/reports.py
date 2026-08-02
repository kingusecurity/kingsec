from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .ports import AuditPublisherPort, CveFilter, CveRepositoryPort, KevFilter, ThreatFeedRepositoryPort


class ThreatReportGenerator:
    def __init__(
        self,
        cve_repo: CveRepositoryPort,
        feed_repo: ThreatFeedRepositoryPort | None = None,
        audit: AuditPublisherPort | None = None,
    ) -> None:
        self._cve_repo = cve_repo
        self._feed_repo = feed_repo
        self._audit = audit

    async def generate_threat_report(self, days: int = 30) -> dict[str, Any]:
        summary = self._cve_repo.get_summary()
        trend_points = self._cve_repo.get_trend_points(days)
        critical = self._cve_repo.find_critical(20)
        kev_entries = self._cve_repo.find_kev_entries(KevFilter(page=1, page_size=50))
        now = datetime.now(UTC).isoformat()

        report = {
            "title": "Threat Intelligence Report",
            "generated_at": now,
            "period_days": days,
            "summary": {
                "total_cves": summary.total_cves,
                "critical": summary.critical_cves,
                "high": summary.high_cves,
                "medium": summary.medium_cves,
                "low": summary.low_cves,
                "kev_count": summary.kev_count,
                "average_threat_score": summary.average_threat_score,
                "feeds_active": summary.feeds_active,
            },
            "trend_points": [
                {"date": tp.date, "new_cves": tp.new_cves, "critical_cves": tp.critical_cves, "average_score": tp.average_score}
                for tp in trend_points
            ],
            "critical_vulnerabilities": [
                {
                    "cve_code": c.cve_code,
                    "severity": c.severity,
                    "threat_score": c.threat_score,
                    "epss_score": c.epss_data.score if c.epss_data else 0,
                    "is_kev": c.is_kev,
                    "exploit_maturity": c.exploit_maturity.value if c.exploit_maturity else "unknown",
                }
                for c in critical
            ],
            "kev_entries": [
                {
                    "cve_id": c.cve_code,
                    "vendor": c.kev_entry.vendor_project if c.kev_entry else "",
                    "product": c.kev_entry.product if c.kev_entry else "",
                    "due_date": c.kev_entry.due_date if c.kev_entry else "",
                    "required_action": c.kev_entry.required_action if c.kev_entry else "",
                }
                for c in kev_entries[0] if c.kev_entry
            ],
        }
        if self._audit:
            await self._audit.publish("report_generated", "threat_report", "report-threat", {"period": days})
        return report

    async def generate_executive_report(self, days: int = 30) -> dict[str, Any]:
        summary = self._cve_repo.get_summary()
        now = datetime.now(UTC).isoformat()
        trending = self._cve_repo.find_trending(10)
        feeds = self._feed_repo.find_all() if self._feed_repo else []

        report = {
            "title": "Executive Threat Report",
            "generated_at": now,
            "period_days": days,
            "executive_summary": f"Period covers {summary.total_cves} CVEs with {summary.critical_cves} critical and {summary.kev_count} known exploited vulnerabilities.",
            "key_metrics": {
                "total_vulnerabilities": summary.total_cves,
                "critical_count": summary.critical_cves,
                "high_count": summary.high_cves,
                "known_exploited": summary.kev_count,
                "active_exploitations": summary.active_exploitations,
                "average_threat_score": summary.average_threat_score,
            },
            "trending_threats": [
                {
                    "cve_code": e.cve_code,
                    "threat_score": e.threat_score,
                    "severity": e.severity,
                    "is_kev": e.is_kev,
                }
                for e in trending
            ],
            "feed_status": [
                {"type": f.feed_type.value, "status": f.status, "last_synced": f.last_synced}
                for f in feeds
            ],
        }
        if self._audit:
            await self._audit.publish("report_generated", "executive_report", "report-executive", {"period": days})
        return report

    async def generate_kev_report(self) -> dict[str, Any]:
        kev_items, total = self._cve_repo.find_kev_entries(KevFilter(page=1, page_size=200))
        now = datetime.now(UTC).isoformat()

        report = {
            "title": "Known Exploited Vulnerabilities Report",
            "generated_at": now,
            "total_entries": total,
            "entries": [
                {
                    "cve_code": c.cve_code,
                    "vendor": c.kev_entry.vendor_project if c.kev_entry else "",
                    "product": c.kev_entry.product if c.kev_entry else "",
                    "date_added": c.kev_entry.date_added if c.kev_entry else "",
                    "due_date": c.kev_entry.due_date if c.kev_entry else "",
                    "required_action": c.kev_entry.required_action if c.kev_entry else "",
                    "ransomware_use": c.kev_entry.known_ransomware_campaign_use if c.kev_entry else False,
                    "threat_score": c.threat_score,
                }
                for c in kev_items if c.kev_entry
            ],
        }
        if self._audit:
            await self._audit.publish("report_generated", "kev_report", "report-kev", {})
        return report

    async def generate_high_risk_cve_report(self, min_score: float = 50.0) -> dict[str, Any]:
        cves, total = self._cve_repo.find_all(
            CveFilter(page=1, page_size=100, min_score=min_score, sort_by="-threat_score")
        )
        now = datetime.now(UTC).isoformat()

        report = {
            "title": f"High-Risk CVE Report (Score >= {min_score})",
            "generated_at": now,
            "min_threat_score": min_score,
            "total_entries": total,
            "entries": [
                {
                    "cve_code": c.cve_code,
                    "description": c.description[:300],
                    "severity": c.severity,
                    "threat_score": c.threat_score,
                    "epss_score": c.epss_data.score if c.epss_data else 0,
                    "cvss_score": c.cvss_data.base_score,
                    "is_kev": c.is_kev,
                    "exploit_maturity": c.exploit_maturity.value if c.exploit_maturity else "unknown",
                    "published_date": c.published_date,
                    "affected_products": [f"{p.vendor}/{p.product} {p.version}" for p in c.affected_products],
                }
                for c in cves
            ],
        }
        if self._audit:
            await self._audit.publish("report_generated", "high_risk_cve_report", "report-high-risk", {"min_score": min_score})
        return report
