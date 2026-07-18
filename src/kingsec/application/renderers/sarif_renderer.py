"""SARIF 2.1.0 Report Renderer — converts Report to SARIF-compliant JSON.

Pure formatting, no business logic, no calculations, no analysis.
Deterministic ordering, UTF-8, pretty-printed JSON.
"""

from __future__ import annotations

import json
from datetime import timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kingsec.application.report import (
        FindingEntry,
        RecommendationEntry,
        RecommendationSection,
        Report,
    )

# ---------------------------------------------------------------------------
# Severity → SARIF level mapping
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------


class SarifRenderer:
    """Renders a Report object into SARIF 2.1.0 JSON."""

    def render(self, report: Report) -> str:
        """Render a Report to a SARIF JSON string."""
        sarif_doc = self._build_sarif(report)
        return json.dumps(sarif_doc, indent=2, ensure_ascii=False, sort_keys=True)

    def write(self, report: Report, path: Path) -> None:
        """Render and write SARIF JSON to a file."""
        path.write_text(self.render(report), encoding="utf-8")

    # ------------------------------------------------------------------
    # SARIF document builder
    # ------------------------------------------------------------------

    def _build_sarif(self, report: Report) -> dict:
        entries = report.finding_section.entries
        recs_by_cid = self._build_recs_lookup(report.recommendation_section)

        rules = self._build_rules(entries, recs_by_cid, report)
        results = self._build_results(entries, recs_by_cid)
        artifacts = self._build_artifacts(entries)

        ts = report.created_at.astimezone(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )

        return {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "KingSec",
                            "version": "1.0.0",
                            "informationUri": "https://kingsec.dev",
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": ts,
                            "endTimeUtc": ts,
                        }
                    ],
                    "rules": rules,
                    "results": results,
                    "artifacts": artifacts,
                    "properties": {
                        "reportId": report.report_id,
                        "title": report.title,
                    },
                }
            ],
        }

    # ------------------------------------------------------------------
    # Recommendations lookup
    # ------------------------------------------------------------------

    @staticmethod
    def _build_recs_lookup(
        section: RecommendationSection,
    ) -> dict[str, list[str]]:
        lookup: dict[str, list[str]] = {}
        for entry in section.entries:
            lookup[entry.correlation_id] = list(entry.recommendations)
        return lookup

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    @staticmethod
    def _build_rules(
        entries: tuple[FindingEntry, ...],
        recs_by_cid: dict[str, list[str]],
        report: Report,
    ) -> list[dict]:
        scanner_versions = report.appendix.scanner_versions
        rules: list[dict] = []
        sorted_entries = sorted(entries, key=lambda e: e.correlation_id)
        for fe in sorted_entries:
            remediation = recs_by_cid.get(fe.correlation_id, [])
            scanners = sorted(fe.scanner_sources)
            scanner_info = [
                {"name": s, "version": scanner_versions.get(s)}
                for s in scanners
            ]

            rule: dict = {
                "id": fe.correlation_id,
                "name": fe.title,
                "shortDescription": {
                    "text": fe.title,
                },
                "fullDescription": {
                    "text": (
                        f"Severity: {fe.severity} | "
                        f"Category: {fe.category} | "
                        f"Risk Score: {fe.risk_score}/100"
                    ),
                },
                "help": {
                    "text": (
                        f"Finding: {fe.title}\n"
                        f"Severity: {fe.severity}\n"
                        f"Category: {fe.category}\n"
                        f"Risk Score: {fe.risk_score}/100\n"
                        f"Confidence: {fe.confidence:.0%}\n"
                        f"Scanners: {', '.join(fe.scanner_sources)}\n"
                        + (
                            f"Remediation: {'; '.join(remediation)}"
                            if remediation
                            else "No remediation available"
                        )
                    ),
                },
                "properties": {
                    "severity": fe.severity,
                    "category": fe.category,
                    "riskScore": fe.risk_score,
                    "confidence": fe.confidence,
                    "scanners": scanner_info,
                    "remediation": remediation,
                },
            }
            rules.append(rule)
        return rules

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    @staticmethod
    def _build_results(
        entries: tuple[FindingEntry, ...],
        recs_by_cid: dict[str, list[str]],
    ) -> list[dict]:
        results: list[dict] = []
        sorted_entries = sorted(entries, key=lambda e: e.correlation_id)
        for rule_idx, fe in enumerate(sorted_entries):
            level = _SEVERITY_MAP.get(fe.severity.upper(), "note")
            remediation = recs_by_cid.get(fe.correlation_id, [])

            locations: list[dict] = []
            for asset in sorted(fe.affected_assets):
                locations.append({
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": asset,
                        },
                    },
                })

            result: dict = {
                "ruleId": fe.correlation_id,
                "ruleIndex": rule_idx,
                "level": level,
                "message": {
                    "text": fe.title,
                },
                "locations": locations,
                "properties": {
                    "riskScore": fe.risk_score,
                    "priority": fe.priority,
                    "confidence": fe.confidence,
                    "riskLevel": fe.risk_level,
                    "service": fe.service,
                    "port": fe.port,
                    "protocol": fe.protocol,
                    "attackSurface": fe.attack_surface,
                    "remediation": remediation,
                },
            }
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    @staticmethod
    def _build_artifacts(
        entries: tuple[FindingEntry, ...],
    ) -> list[dict]:
        seen: set[str] = set()
        artifacts: list[dict] = []
        for fe in entries:
            for asset in fe.affected_assets:
                if asset not in seen:
                    seen.add(asset)
                    artifacts.append({
                        "location": {"uri": asset},
                        "description": {"text": "Affected asset"},
                    })
        artifacts.sort(key=lambda a: a["location"]["uri"])
        return artifacts
