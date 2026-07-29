from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from kingsec.application.monitoring.detectors import AssetChangeDetector, FindingChangeDetector
from kingsec.application.monitoring.service import MonitoringService
from kingsec.domain.monitoring import MonitorEvent, MonitorEventType


class MonitoringScheduler:
    """Reuses the existing scheduling infrastructure.

    The existing ``ScheduleServicePort`` and ``JobServicePort`` are used to
    schedule periodic monitoring scans. This class provides the monitoring-specific
    logic that gets invoked when those schedules fire.
    """

    def __init__(
        self,
        monitoring_service: MonitoringService,
        asset_detector: AssetChangeDetector | None = None,
        finding_detector: FindingChangeDetector | None = None,
    ) -> None:
        self._service = monitoring_service
        self._asset_detector = asset_detector or AssetChangeDetector()
        self._finding_detector = finding_detector or FindingChangeDetector()

    def run_scheduled_check(self) -> list[MonitorEvent]:
        """Called by the scheduler infrastructure when a monitoring job fires."""
        events: list[MonitorEvent] = []
        now = datetime.now(UTC).isoformat()
        heartbeat = MonitorEvent.create(
            MonitorEventType.ASSET_UPDATED,
            source="scheduler",
            title="Scheduled monitoring check",
            description=f"Scheduled monitoring run at {now}",
        )
        self._service.record_event(heartbeat)
        events.append(heartbeat)
        return events

    def get_schedule_config(self) -> dict[str, Any]:
        """Returns the default monitoring schedule configuration."""
        return {
            "name": "Continuous Monitoring Scan",
            "description": "Periodic scan to detect changes in assets, findings, and exposures",
            "schedule_type": "interval",
            "cron_expression": "",
            "interval_minutes": 60,
            "enabled": True,
        }
