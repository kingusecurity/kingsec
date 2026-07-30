"""Benchmark suite for KingSec performance validation.

Run with: python -m tests.benchmarks.benchmark_suite
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any


def _timer(func: Any, *args: Any, **kwargs: Any) -> tuple[Any, float]:
    start = time.perf_counter()
    result = func(*args, **kwargs)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return result, elapsed_ms


def benchmark_cache_operations(iterations: int = 10000) -> dict[str, Any]:
    """Benchmark in-memory cache set/get/delete operations."""
    from kingsec.infrastructure.cache.memory_cache import MemoryCacheService

    cache = MemoryCacheService(max_size=5000, default_ttl=300)
    results: dict[str, Any] = {}

    # Set operations
    _, set_ms = _timer(
        lambda: [cache.set_sync(f"key-{i}", f"value-{i}", ttl=60) for i in range(iterations)]
    )
    results["set_ops"] = {"iterations": iterations, "total_ms": round(set_ms, 2), "ops_per_sec": round(iterations / (set_ms / 1000), 0)}

    # Get operations (all hits)
    _, get_hit_ms = _timer(
        lambda: [cache.get_sync(f"key-{i}") for i in range(iterations)]
    )
    results["get_hit_ops"] = {"iterations": iterations, "total_ms": round(get_hit_ms, 2), "ops_per_sec": round(iterations / (get_hit_ms / 1000), 0)}

    # Get operations (all misses)
    _, get_miss_ms = _timer(
        lambda: [cache.get_sync(f"missing-{i}") for i in range(iterations)]
    )
    results["get_miss_ops"] = {"iterations": iterations, "total_ms": round(get_miss_ms, 2), "ops_per_sec": round(iterations / (get_miss_ms / 1000), 0)}

    # Delete operations
    _, del_ms = _timer(
        lambda: [cache.delete_sync(f"key-{i}") for i in range(iterations)]
    )
    results["delete_ops"] = {"iterations": iterations, "total_ms": round(del_ms, 2), "ops_per_sec": round(iterations / (del_ms / 1000), 0)}

    results["hit_ratio"] = round(cache.hit_ratio, 4)
    return results


def benchmark_metrics_collection(iterations: int = 10000) -> dict[str, Any]:
    """Benchmark performance metrics recording and snapshot."""
    from kingsec.infrastructure.monitoring.performance_metrics import PerformanceMetrics

    metrics = PerformanceMetrics()
    results: dict[str, Any] = {}

    # Record requests
    _, record_ms = _timer(
        lambda: [metrics.record_request(float(i) * 0.1, is_error=(i % 100 == 0)) for i in range(iterations)]
    )
    results["record_requests"] = {"iterations": iterations, "total_ms": round(record_ms, 2)}

    # Record operations
    _, ops_ms = _timer(
        lambda: [metrics.record_operation("assessment", float(i) * 0.5) for i in range(iterations)]
    )
    results["record_operations"] = {"iterations": iterations, "total_ms": round(ops_ms, 2)}

    # Snapshot
    _, snap_ms = _timer(lambda: metrics.snapshot())
    results["snapshot"] = {"total_ms": round(snap_ms, 2)}

    # Operation stats
    _, stats_ms = _timer(lambda: metrics.get_operation_stats("assessment"))
    results["operation_stats"] = {"total_ms": round(stats_ms, 2)}

    return results


def benchmark_domain_operations(iterations: int = 1000) -> dict[str, Any]:
    """Benchmark domain entity creation and serialization."""
    from kingsec.domain.backup import BackupId, BackupMetadata, BackupStatus, BackupType

    results: dict[str, Any] = {}

    # BackupMetadata creation
    _, create_ms = _timer(
        lambda: [
            BackupMetadata(
                backup_id=BackupId(value=f"bkp-{i}"),
                backup_type=BackupType.FULL,
                status=BackupStatus.COMPLETED,
                size_bytes=i * 1024,
                checksum=f"sha256-{i}",
            )
            for i in range(iterations)
        ]
    )
    results["backup_creation"] = {"iterations": iterations, "total_ms": round(create_ms, 2)}

    # BackupId creation
    _, id_ms = _timer(lambda: [BackupId(value=f"id-{i}") for i in range(iterations)])
    results["backup_id_creation"] = {"iterations": iterations, "total_ms": round(id_ms, 2)}

    return results


def benchmark_json_serialization(iterations: int = 5000) -> dict[str, Any]:
    """Benchmark JSON serialization of typical API responses."""
    sample_payload = {
        "backups": [
            {
                "backup_id": f"bkp-{i}",
                "backup_type": "full",
                "status": "completed",
                "size_bytes": i * 1024,
                "checksum": f"sha256-{i}",
                "encrypted": True,
                "compressed": True,
            }
            for i in range(50)
        ],
        "total": 50,
    }

    results: dict[str, Any] = {}

    _, dumps_ms = _timer(
        lambda: [json.dumps(sample_payload) for _ in range(iterations)]
    )
    results["json_dumps"] = {"iterations": iterations, "total_ms": round(dumps_ms, 2), "size_bytes": len(json.dumps(sample_payload))}

    serialized = json.dumps(sample_payload)
    _, loads_ms = _timer(
        lambda: [json.loads(serialized) for _ in range(iterations)]
    )
    results["json_loads"] = {"iterations": iterations, "total_ms": round(loads_ms, 2)}

    return results


def run_all_benchmarks() -> dict[str, Any]:
    """Run all benchmarks and return results."""
    print("Running KingSec benchmarks...")
    print("=" * 60)

    results: dict[str, Any] = {}

    print("\n[1/4] Cache operations...")
    results["cache"] = benchmark_cache_operations()
    print(f"  Set: {results['cache']['set_ops']['ops_per_sec']:.0f} ops/sec")
    print(f"  Get (hit): {results['cache']['get_hit_ops']['ops_per_sec']:.0f} ops/sec")
    print(f"  Hit ratio: {results['cache']['hit_ratio']}")

    print("\n[2/4] Metrics collection...")
    results["metrics"] = benchmark_metrics_collection()
    print(f"  Record: {results['metrics']['record_requests']['total_ms']:.1f}ms for 10k")
    print(f"  Snapshot: {results['metrics']['snapshot']['total_ms']:.2f}ms")

    print("\n[3/4] Domain operations...")
    results["domain"] = benchmark_domain_operations()
    print(f"  Creation: {results['domain']['backup_creation']['total_ms']:.1f}ms for 1k")

    print("\n[4/4] JSON serialization...")
    results["json"] = benchmark_json_serialization()
    print(f"  Dumps: {results['json']['json_dumps']['total_ms']:.1f}ms for 5k")
    print(f"  Loads: {results['json']['json_loads']['total_ms']:.1f}ms for 5k")

    print("\n" + "=" * 60)
    print("Benchmarks complete.")
    return results


if __name__ == "__main__":
    results = run_all_benchmarks()
    if "--json" in sys.argv:
        print(json.dumps(results, indent=2))
