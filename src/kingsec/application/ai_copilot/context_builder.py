from __future__ import annotations

from typing import Any, Protocol


class FindingRepositoryPort(Protocol):
    def find_by_id(self, finding_id: str) -> Any | None: ...


class AssessmentRepositoryPort(Protocol):
    def find_by_id(self, assessment_id: str) -> Any | None: ...


class AssetRepositoryPort(Protocol):
    def find_by_id(self, asset_id: str) -> Any | None: ...


class CveRepositoryPort(Protocol):
    def find_by_cve_code(self, cve_code: str) -> Any | None: ...


class AlertRepositoryPort(Protocol):
    def find_by_id(self, alert_id: str) -> Any | None: ...


class ExposureRepositoryPort(Protocol):
    def find_by_id(self, exposure_id: str) -> Any | None: ...


class CopilotContextBuilder:
    def __init__(
        self,
        finding_repo: FindingRepositoryPort | None = None,
        assessment_repo: AssessmentRepositoryPort | None = None,
        asset_repo: AssetRepositoryPort | None = None,
        cve_repo: CveRepositoryPort | None = None,
        alert_repo: AlertRepositoryPort | None = None,
        exposure_repo: ExposureRepositoryPort | None = None,
    ) -> None:
        self._finding_repo = finding_repo
        self._assessment_repo = assessment_repo
        self._asset_repo = asset_repo
        self._cve_repo = cve_repo
        self._alert_repo = alert_repo
        self._exposure_repo = exposure_repo

    def build_context(
        self,
        investigation_type: str,
        entity_id: str,
    ) -> dict[str, Any]:
        context: dict[str, Any] = {
            "investigation_type": investigation_type,
            "entity_id": entity_id,
            "finding": None,
            "assessment": None,
            "asset": None,
            "cve": None,
            "alert": None,
            "exposure": None,
            "related": {},
        }

        if investigation_type == "finding":
            context["finding"] = self._get_finding(entity_id)
            if context["finding"]:
                assoc_id = context["finding"].get("assessment_id")
                asset_id = context["finding"].get("asset_id")
                if assoc_id:
                    context["assessment"] = self._get_assessment(assoc_id)
                if asset_id:
                    context["asset"] = self._get_asset(asset_id)

        elif investigation_type == "assessment":
            context["assessment"] = self._get_assessment(entity_id)

        elif investigation_type == "asset":
            context["asset"] = self._get_asset(entity_id)

        elif investigation_type == "cve":
            context["cve"] = self._get_cve(entity_id)

        elif investigation_type == "alert":
            context["alert"] = self._get_alert(entity_id)
            if context["alert"]:
                assoc_id = context["alert"].get("assessment_id")
                asset_id = context["alert"].get("asset_id")
                if assoc_id:
                    context["assessment"] = self._get_assessment(assoc_id)
                if asset_id:
                    context["asset"] = self._get_asset(asset_id)

        elif investigation_type == "exposure":
            context["exposure"] = self._get_exposure(entity_id)
            if context["exposure"]:
                asset_id = context["exposure"].get("asset_id")
                if asset_id:
                    context["asset"] = self._get_asset(asset_id)

        return context

    def _get_finding(self, finding_id: str) -> dict[str, Any] | None:
        if not self._finding_repo:
            return None
        try:
            finding = self._finding_repo.find_by_id(finding_id)
            if finding is None:
                return None
            return {
                "id": str(getattr(finding, "id", finding_id)),
                "title": getattr(finding, "title", ""),
                "description": getattr(finding, "description", ""),
                "severity": getattr(finding, "severity", ""),
                "status": getattr(finding, "status", ""),
                "assessment_id": str(getattr(finding, "assessment_id", "")),
                "asset_id": str(getattr(finding, "asset_id", "")),
            }
        except Exception:
            return None

    def _get_assessment(self, assessment_id: str) -> dict[str, Any] | None:
        if not self._assessment_repo:
            return None
        try:
            assessment = self._assessment_repo.find_by_id(assessment_id)
            if assessment is None:
                return None
            return {
                "id": str(getattr(assessment, "id", assessment_id)),
                "target": str(getattr(assessment, "target", "")),
                "status": getattr(assessment, "status", ""),
                "finding_count": len(getattr(assessment, "findings", [])),
            }
        except Exception:
            return None

    def _get_asset(self, asset_id: str) -> dict[str, Any] | None:
        if not self._asset_repo:
            return None
        try:
            asset = self._asset_repo.find_by_id(asset_id)
            if asset is None:
                return None
            return {
                "id": str(getattr(asset, "id", asset_id)),
                "hostname": getattr(asset, "hostname", ""),
                "ip_address": getattr(asset, "ip_address", ""),
                "asset_type": getattr(asset, "asset_type", ""),
                "criticality": getattr(asset, "criticality", ""),
            }
        except Exception:
            return None

    def _get_cve(self, cve_id: str) -> dict[str, Any] | None:
        if not self._cve_repo:
            return None
        try:
            cve = self._cve_repo.find_by_cve_code(cve_id)
            if cve is None:
                return None
            return {
                "cve_code": getattr(cve, "cve_code", cve_id),
                "description": getattr(cve, "description", ""),
                "severity": getattr(cve, "severity", ""),
                "threat_score": getattr(cve, "threat_score", 0),
                "cvss_score": getattr(getattr(cve, "cvss_data", None), "base_score", 0),
                "is_kev": getattr(cve, "is_kev", False),
            }
        except Exception:
            return None

    def _get_alert(self, alert_id: str) -> dict[str, Any] | None:
        if not self._alert_repo:
            return None
        try:
            alert = self._alert_repo.find_by_id(alert_id)
            if alert is None:
                return None
            return {
                "id": str(getattr(alert, "id", alert_id)),
                "title": getattr(alert, "title", ""),
                "description": getattr(alert, "description", ""),
                "severity": getattr(alert, "severity", ""),
                "status": getattr(alert, "status", ""),
                "assessment_id": str(getattr(alert, "assessment_id", "")),
                "asset_id": str(getattr(alert, "asset_id", "")),
            }
        except Exception:
            return None

    def _get_exposure(self, exposure_id: str) -> dict[str, Any] | None:
        if not self._exposure_repo:
            return None
        try:
            exposure = self._exposure_repo.find_by_id(exposure_id)
            if exposure is None:
                return None
            return {
                "id": str(getattr(exposure, "id", exposure_id)),
                "exposure_type": getattr(exposure, "exposure_type", ""),
                "severity": getattr(exposure, "severity", ""),
                "asset_id": str(getattr(exposure, "asset_id", "")),
            }
        except Exception:
            return None
