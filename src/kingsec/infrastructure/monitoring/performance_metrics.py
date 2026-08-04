"""Application performance metrics collector."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from kingsec.application.ports.outbound.performance_metrics import PerformanceMetricsPort


@dataclass(frozen=True)
class LatencyStats:
    """Aggregated latency statistics for a metric."""

    count: int = 0
    total_ms: float = 0.0
    min_ms: float = 0.0
    max_ms: float = 0.0
    avg_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0


@dataclass(frozen=True)
class ThroughputStats:
    """Requests per second over a time window."""

    window_seconds: float = 60.0
    requests_per_second: float = 0.0
    total_requests: int = 0
    error_count: int = 0
    error_rate: float = 0.0


@dataclass(frozen=True)
class CacheStats:
    """Cache hit/miss statistics."""

    hits: int = 0
    misses: int = 0
    hit_ratio: float = 0.0
    size: int = 0


@dataclass(frozen=True)
class PerformanceSnapshot:
    """Complete performance snapshot at a point in time."""

    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    request_latency: LatencyStats = field(default_factory=LatencyStats)
    api_latency: LatencyStats = field(default_factory=LatencyStats)
    db_latency: LatencyStats = field(default_factory=LatencyStats)
    cache_stats: CacheStats = field(default_factory=CacheStats)
    throughput: ThroughputStats = field(default_factory=ThroughputStats)
    worker_count: int = 0
    queue_depth: int = 0
    assessment_count: int = 0
    report_count: int = 0
    backup_count: int = 0
    uptime_seconds: float = 0.0


class PerformanceMetrics(PerformanceMetricsPort):
    """Thread-safe application performance metrics collector.

    Tracks request latency, database latency, cache performance,
    throughput, and operation durations. All operations are lock-free
    where possible using atomic counters.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._start_time = time.monotonic()
        self._request_latencies: list[float] = []
        self._api_latencies: list[float] = []
        self._db_latencies: list[float] = []
        self._request_times: list[float] = []
        self._error_count = 0
        self._total_requests = 0
        self._assessment_count = 0
        self._report_count = 0
        self._backup_count = 0
        self._worker_count = 0
        self._queue_depth = 0
        self._cache_hits = 0
        self._cache_misses = 0
        self._operation_durations: dict[str, list[float]] = {}
        self._max_samples = 10000

    def record_request(self, latency_ms: float, is_error: bool = False) -> None:
        """Record an API request with its latency."""
        with self._lock:
            self._request_latencies.append(latency_ms)
            if len(self._request_latencies) > self._max_samples:
                self._request_latencies = self._request_latencies[-self._max_samples:]
            self._request_times.append(time.monotonic())
            self._total_requests += 1
            if is_error:
                self._error_count += 1

    def record_api_latency(self, latency_ms: float) -> None:
        """Record API endpoint latency."""
        with self._lock:
            self._api_latencies.append(latency_ms)
            if len(self._api_latencies) > self._max_samples:
                self._api_latencies = self._api_latencies[-self._max_samples:]

    def record_db_latency(self, latency_ms: float) -> None:
        """Record database query latency."""
        with self._lock:
            self._db_latencies.append(latency_ms)
            if len(self._db_latencies) > self._max_samples:
                self._db_latencies = self._db_latencies[-self._max_samples:]

    def record_cache_hit(self) -> None:
        with self._lock:
            self._cache_hits += 1

    def record_cache_miss(self) -> None:
        with self._lock:
            self._cache_misses += 1

    def record_operation(self, operation_name: str, duration_ms: float) -> None:
        """Record an operation duration (assessment, report, backup, etc.)."""
        with self._lock:
            if operation_name not in self._operation_durations:
                self._operation_durations[operation_name] = []
            durations = self._operation_durations[operation_name]
            durations.append(duration_ms)
            if len(durations) > self._max_samples:
                self._operation_durations[operation_name] = durations[-self._max_samples:]

    def set_worker_count(self, count: int) -> None:
        with self._lock:
            self._worker_count = count

    def set_queue_depth(self, depth: int) -> None:
        with self._lock:
            self._queue_depth = depth

    def increment_assessment(self) -> None:
        with self._lock:
            self._assessment_count += 1

    def increment_report(self) -> None:
        with self._lock:
            self._report_count += 1

    def increment_backup(self) -> None:
        with self._lock:
            self._backup_count += 1

    def _compute_latency_stats(self, samples: list[float]) -> LatencyStats:
        if not samples:
            return LatencyStats()
        sorted_samples = sorted(samples)
        count = len(sorted_samples)
        total = sum(sorted_samples)
        p95_idx = max(0, int(count * 0.95) - 1)
        p99_idx = max(0, int(count * 0.99) - 1)
        return LatencyStats(
            count=count,
            total_ms=total,
            min_ms=sorted_samples[0],
            max_ms=sorted_samples[-1],
            avg_ms=total / count,
            p95_ms=sorted_samples[p95_idx],
            p99_ms=sorted_samples[p99_idx],
        )

    def snapshot(self) -> PerformanceSnapshot:
        """Capture a point-in-time performance snapshot."""
        now = time.monotonic()
        window = 60.0
        with self._lock:
            recent = [t for t in self._request_times if now - t <= window]
            rps = len(recent) / window if window > 0 else 0.0
            total_req = self._total_requests
            err_count = self._error_count
            error_rate = err_count / total_req if total_req > 0 else 0.0
            cache_hits = self._cache_hits
            cache_misses = self._cache_misses
            cache_total = cache_hits + cache_misses
            hit_ratio = cache_hits / cache_total if cache_total > 0 else 0.0
            return PerformanceSnapshot(
                request_latency=self._compute_latency_stats(list(self._request_latencies)),
                api_latency=self._compute_latency_stats(list(self._api_latencies)),
                db_latency=self._compute_latency_stats(list(self._db_latencies)),
                cache_stats=CacheStats(
                    hits=cache_hits,
                    misses=cache_misses,
                    hit_ratio=hit_ratio,
                ),
                throughput=ThroughputStats(
                    window_seconds=window,
                    requests_per_second=rps,
                    total_requests=total_req,
                    error_count=err_count,
                    error_rate=error_rate,
                ),
                worker_count=self._worker_count,
                queue_depth=self._queue_depth,
                assessment_count=self._assessment_count,
                report_count=self._report_count,
                backup_count=self._backup_count,
                uptime_seconds=now - self._start_time,
            )

    def get_operation_stats(self, operation_name: str) -> LatencyStats:
        with self._lock:
            durations = list(self._operation_durations.get(operation_name, []))
        return self._compute_latency_stats(durations)

    def reset(self) -> None:
        with self._lock:
            self._request_latencies.clear()
            self._api_latencies.clear()
            self._db_latencies.clear()
            self._request_times.clear()
            self._error_count = 0
            self._total_requests = 0
            self._cache_hits = 0
            self._cache_misses = 0
            self._operation_durations.clear()
