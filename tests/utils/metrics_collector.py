"""Performance metrics collection for load testing."""

from __future__ import annotations

import statistics
import time
from typing import Any


class MetricsCollector:
    """Collect and analyze performance metrics during load testing."""

    def __init__(self):
        self.latencies: list[float] = []
        self.errors: list[bool] = []
        self.memory_samples: list[int] = []
        self.start_time: float | None = None
        self.end_time: float | None = None

    def start(self) -> None:
        """Start metrics collection."""
        self.start_time = time.time()

    def stop(self) -> None:
        """Stop metrics collection."""
        self.end_time = time.time()

    def record_request(self, latency_ms: float, error: bool = False) -> None:
        """Record single request metrics.

        Args:
            latency_ms: Request latency in milliseconds
            error: Whether the request resulted in an error
        """
        self.latencies.append(latency_ms)
        if error:
            self.errors.append(True)

    def record_memory(self, memory_bytes: int) -> None:
        """Record memory usage sample.

        Args:
            memory_bytes: Memory usage in bytes
        """
        self.memory_samples.append(memory_bytes)

    def _percentile(self, p: int) -> float:
        """Calculate percentile of latencies.

        Args:
            p: Percentile (0-100)

        Returns:
            Latency at given percentile
        """
        if not self.latencies:
            return 0.0
        sorted_latencies = sorted(self.latencies)
        index = int(len(sorted_latencies) * p / 100)
        if index >= len(sorted_latencies):
            index = len(sorted_latencies) - 1
        return sorted_latencies[index]

    def get_summary(self) -> dict[str, Any]:
        """Calculate summary statistics.

        Returns:
            Dictionary of metrics
        """
        if not self.latencies:
            return {
                "total_requests": 0,
                "error_rate": 0.0,
                "throughput_rps": 0.0,
            }

        duration = (
            (self.end_time - self.start_time)
            if self.start_time and self.end_time
            else 1.0
        )

        return {
            "total_requests": len(self.latencies),
            "error_count": len(self.errors),
            "error_rate": len(self.errors) / len(self.latencies),
            "latency_min": min(self.latencies),
            "latency_max": max(self.latencies),
            "latency_mean": statistics.mean(self.latencies),
            "latency_median": statistics.median(self.latencies),
            "latency_p50": self._percentile(50),
            "latency_p95": self._percentile(95),
            "latency_p99": self._percentile(99),
            "throughput_rps": len(self.latencies) / duration,
            "duration_sec": duration,
            "memory_avg_mb": (
                statistics.mean(self.memory_samples) / (1024 * 1024)
                if self.memory_samples
                else 0.0
            ),
            "memory_max_mb": (
                max(self.memory_samples) / (1024 * 1024) if self.memory_samples else 0.0
            ),
        }

    def print_summary(self) -> None:
        """Print formatted summary statistics."""
        summary = self.get_summary()
        print("\n=== Load Test Summary ===")
        print(f"Total Requests: {summary['total_requests']}")
        print(f"Duration: {summary['duration_sec']:.2f}s")
        print(f"Throughput: {summary['throughput_rps']:.2f} req/sec")
        print("\nLatency (ms):")
        print(f"  Min:    {summary['latency_min']:.2f}")
        print(f"  Mean:   {summary['latency_mean']:.2f}")
        print(f"  Median: {summary['latency_median']:.2f}")
        print(f"  P95:    {summary['latency_p95']:.2f}")
        print(f"  P99:    {summary['latency_p99']:.2f}")
        print(f"  Max:    {summary['latency_max']:.2f}")
        print(
            f"\nErrors: {summary['error_count']} ({summary['error_rate'] * 100:.2f}%)"
        )
        if summary["memory_avg_mb"] > 0:
            print("\nMemory:")
            print(f"  Avg: {summary['memory_avg_mb']:.2f} MB")
            print(f"  Max: {summary['memory_max_mb']:.2f} MB")
