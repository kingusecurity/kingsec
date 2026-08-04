"""Tests for PerformanceMetrics."""

from __future__ import annotations

import pytest

from kingsec.application.ports.outbound.performance_metrics import PerformanceMetricsPort
from kingsec.infrastructure.monitoring.performance_metrics import PerformanceMetrics


class TestPerformanceMetricsPort:
    def test_is_a_performance_metrics_port(self) -> None:
        # metrics_routes.py resolves this by PerformanceMetricsPort, not the
        # concrete class, to avoid an application/adapter -> infrastructure
        # import-linter violation.
        assert isinstance(PerformanceMetrics(), PerformanceMetricsPort)


class TestPerformanceMetrics:
    def test_record_request(self) -> None:
        metrics = PerformanceMetrics()
        metrics.record_request(10.5)
        metrics.record_request(20.0, is_error=True)
        snap = metrics.snapshot()
        assert snap.request_latency.count == 2
        assert snap.throughput.total_requests == 2
        assert snap.throughput.error_count == 1

    def test_record_api_latency(self) -> None:
        metrics = PerformanceMetrics()
        metrics.record_api_latency(5.0)
        metrics.record_api_latency(15.0)
        snap = metrics.snapshot()
        assert snap.api_latency.count == 2
        assert snap.api_latency.min_ms == 5.0
        assert snap.api_latency.max_ms == 15.0

    def test_record_db_latency(self) -> None:
        metrics = PerformanceMetrics()
        metrics.record_db_latency(1.0)
        metrics.record_db_latency(3.0)
        snap = metrics.snapshot()
        assert snap.db_latency.count == 2

    def test_cache_metrics(self) -> None:
        metrics = PerformanceMetrics()
        metrics.record_cache_hit()
        metrics.record_cache_hit()
        metrics.record_cache_miss()
        snap = metrics.snapshot()
        assert snap.cache_stats.hits == 2
        assert snap.cache_stats.misses == 1
        assert snap.cache_stats.hit_ratio == pytest.approx(2 / 3, abs=0.01)

    def test_operation_metrics(self) -> None:
        metrics = PerformanceMetrics()
        metrics.record_operation("assessment", 100.0)
        metrics.record_operation("assessment", 200.0)
        stats = metrics.get_operation_stats("assessment")
        assert stats.count == 2
        assert stats.min_ms == 100.0
        assert stats.max_ms == 200.0
        assert stats.avg_ms == 150.0

    def test_operation_metrics_empty(self) -> None:
        metrics = PerformanceMetrics()
        stats = metrics.get_operation_stats("nonexistent")
        assert stats.count == 0

    def test_worker_count(self) -> None:
        metrics = PerformanceMetrics()
        metrics.set_worker_count(5)
        snap = metrics.snapshot()
        assert snap.worker_count == 5

    def test_queue_depth(self) -> None:
        metrics = PerformanceMetrics()
        metrics.set_queue_depth(42)
        snap = metrics.snapshot()
        assert snap.queue_depth == 42

    def test_counters(self) -> None:
        metrics = PerformanceMetrics()
        metrics.increment_assessment()
        metrics.increment_assessment()
        metrics.increment_report()
        metrics.increment_backup()
        snap = metrics.snapshot()
        assert snap.assessment_count == 2
        assert snap.report_count == 1
        assert snap.backup_count == 1

    def test_uptime(self) -> None:
        metrics = PerformanceMetrics()
        snap = metrics.snapshot()
        assert snap.uptime_seconds >= 0

    def test_latency_percentiles(self) -> None:
        metrics = PerformanceMetrics()
        for i in range(100):
            metrics.record_request(float(i))
        snap = metrics.snapshot()
        assert snap.request_latency.p95_ms >= 0
        assert snap.request_latency.p99_ms >= 0
        assert snap.request_latency.min_ms == 0.0
        assert snap.request_latency.max_ms == 99.0

    def test_reset(self) -> None:
        metrics = PerformanceMetrics()
        metrics.record_request(10.0)
        metrics.record_operation("test", 5.0)
        metrics.reset()
        snap = metrics.snapshot()
        assert snap.request_latency.count == 0
        assert snap.throughput.total_requests == 0

    def test_snapshot_returns_frozen_dataclass(self) -> None:
        metrics = PerformanceMetrics()
        snap = metrics.snapshot()
        assert hasattr(snap, "timestamp")
        assert hasattr(snap, "request_latency")
        assert hasattr(snap, "throughput")
        assert hasattr(snap, "cache_stats")
