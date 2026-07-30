"""Privacy-first product telemetry.

Collects anonymous usage metrics: feature usage, session duration,
error rates, and performance stats. No PII is ever transmitted.
All data is local-first with optional opt-in remote reporting.
"""

from __future__ import annotations

import datetime
import json
import platform
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class UsageEvent:
    """A single anonymous usage event."""

    event_type: str
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat()
    )
    duration_ms: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionMetrics:
    """Aggregated metrics for a session."""

    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat()
    )
    ended_at: str | None = None
    events: list[UsageEvent] = field(default_factory=list)
    feature_usage: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    error_count: int = 0
    api_calls: int = 0
    total_duration_ms: float = 0.0


@dataclass(frozen=True)
class ProductTelemetryConfig:
    """Configuration for telemetry collection."""

    enabled: bool = True
    collect_local: bool = True
    remote_endpoint: str | None = None
    flush_interval_seconds: int = 300  # 5 minutes
    max_events: int = 10000
    anonymize_ip: bool = True


class ProductTelemetry:
    """Collects and stores anonymous product usage metrics."""

    def __init__(
        self,
        data_dir: Path,
        config: ProductTelemetryConfig | None = None,
    ) -> None:
        self._data_dir = data_dir
        self._config = config or ProductTelemetryConfig()
        self._session = SessionMetrics()
        self._events: list[UsageEvent] = []
        self._metrics_dir = data_dir / "telemetry"
        self._metrics_dir.mkdir(parents=True, exist_ok=True)

    @property
    def is_enabled(self) -> bool:
        return self._config.enabled

    def record_event(
        self,
        event_type: str,
        duration_ms: float | None = None,
        **metadata: Any,
    ) -> None:
        """Record an anonymous usage event."""
        if not self._config.enabled:
            return

        event = UsageEvent(
            event_type=event_type,
            duration_ms=duration_ms,
            metadata=metadata,
        )
        self._events.append(event)
        self._session.events.append(event)
        self._session.feature_usage[event_type] += 1

        if len(self._events) >= self._config.max_events:
            self.flush()

    def record_api_call(self, endpoint: str, method: str, status_code: int) -> None:
        """Record an API call metric."""
        self.record_event(
            "api_call",
            metadata={"endpoint": endpoint, "method": method, "status": status_code},
        )
        self._session.api_calls += 1

    def record_error(self, error_type: str, component: str) -> None:
        """Record an error event."""
        self.record_event(
            "error",
            metadata={"error_type": error_type, "component": component},
        )
        self._session.error_count += 1

    def record_feature_usage(self, feature: str) -> None:
        """Record feature usage."""
        self.record_event("feature_used", metadata={"feature": feature})

    def end_session(self) -> SessionMetrics:
        """End the current session and persist metrics."""
        self._session.ended_at = datetime.datetime.now(datetime.UTC).isoformat()

        # Calculate total duration
        if self._session.started_at and self._session.ended_at:
            start = datetime.datetime.fromisoformat(self._session.started_at)
            end = datetime.datetime.fromisoformat(self._session.ended_at)
            self._session.total_duration_ms = (end - start).total_seconds() * 1000

        if self._config.collect_local:
            self._persist_session(self._session)

        return self._session

    def flush(self) -> None:
        """Flush pending events to disk."""
        if not self._events:
            return

        batch = self._events[:]
        self._events.clear()

        if self._config.collect_local:
            self._persist_events(batch)

    def get_summary(self, days: int = 30) -> dict[str, Any]:
        """Get a summary of telemetry data for the past N days."""
        sessions = self._load_recent_sessions(days)

        total_events = sum(len(s.events) for s in sessions)
        total_errors = sum(s.error_count for s in sessions)
        total_api_calls = sum(s.api_calls for s in sessions)

        feature_totals: dict[str, int] = defaultdict(int)
        for session in sessions:
            for feature, count in session.feature_usage.items():
                feature_totals[feature] += count

        return {
            "period_days": days,
            "total_sessions": len(sessions),
            "total_events": total_events,
            "total_errors": total_errors,
            "total_api_calls": total_api_calls,
            "top_features": dict(
                sorted(feature_totals.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "avg_session_duration_ms": (
                sum(s.total_duration_ms for s in sessions) / len(sessions)
                if sessions
                else 0
            ),
        }

    def _persist_session(self, session: SessionMetrics) -> None:
        """Persist a session to disk."""
        date_str = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d")
        session_file = self._metrics_dir / f"sessions-{date_str}.jsonl"
        with open(session_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(session), default=str) + "\n")

    def _persist_events(self, events: list[UsageEvent]) -> None:
        """Persist events to disk."""
        date_str = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d")
        events_file = self._metrics_dir / f"events-{date_str}.jsonl"
        with open(events_file, "a", encoding="utf-8") as f:
            for event in events:
                f.write(json.dumps(asdict(event), default=str) + "\n")

    def _load_recent_sessions(self, days: int) -> list[SessionMetrics]:
        """Load sessions from the past N days."""
        sessions: list[SessionMetrics] = []
        for i in range(days):
            date = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=i)
            date_str = date.strftime("%Y-%m-%d")
            session_file = self._metrics_dir / f"sessions-{date_str}.jsonl"
            if session_file.is_file():
                with open(session_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                sessions.append(
                                    SessionMetrics(
                                        session_id=data.get("session_id", ""),
                                        started_at=data.get("started_at", ""),
                                        ended_at=data.get("ended_at"),
                                        feature_usage=data.get("feature_usage", {}),
                                        error_count=data.get("error_count", 0),
                                        api_calls=data.get("api_calls", 0),
                                        total_duration_ms=data.get("total_duration_ms", 0.0),
                                    )
                                )
                            except (json.JSONDecodeError, TypeError):
                                continue
        return sessions

    def get_system_info(self) -> dict[str, Any]:
        """Get non-identifying system info for telemetry."""
        return {
            "os": platform.system(),
            "python": platform.python_version(),
            "machine": platform.machine(),
            # No hostname, no IP, no user info
        }
