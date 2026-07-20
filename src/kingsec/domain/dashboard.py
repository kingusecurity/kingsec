"""Dashboard domain model: summary and statistics views."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DashboardSummary:
    total_scans: int = 0
    successful_scans: int = 0
    failed_scans: int = 0
    average_duration_seconds: float = 0.0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    active_scanners: int = 0
    active_schedules: int = 0
    pending_notifications: int = 0
    failed_notifications: int = 0


@dataclass(frozen=True)
class SeverityBreakdown:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


@dataclass(frozen=True)
class TrendPoint:
    date: str
    value: float


@dataclass(frozen=True)
class ScannerStatistics:
    scanner_id: str
    name: str
    total_scans: int = 0
    successful_scans: int = 0
    failed_scans: int = 0
    average_duration_seconds: float = 0.0


@dataclass(frozen=True)
class WorkerStatistics:
    worker_id: str
    status: str = "stopped"
    uptime_seconds: float = 0.0
    jobs_completed: int = 0
    jobs_failed: int = 0
    current_job_id: str | None = None


@dataclass(frozen=True)
class ScheduleStatistics:
    total: int = 0
    active: int = 0
    paused: int = 0
    disabled: int = 0


@dataclass(frozen=True)
class JobStatistics:
    pending: int = 0
    running: int = 0
    completed: int = 0
    failed: int = 0
    cancelled: int = 0
    average_duration_seconds: float = 0.0


@dataclass(frozen=True)
class NotificationStatistics:
    total: int = 0
    sent: int = 0
    failed: int = 0
    pending: int = 0
    read_count: int = 0
