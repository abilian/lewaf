"""Performance benchmarking suite for regression detection."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from lewaf.integration import WAF
from lewaf.primitives import transformations
from lewaf.primitives.operators import OperatorOptions, get_operator


class BenchmarkSuite:
    """Performance benchmarking utilities."""

    def __init__(self):
        self.results: dict[str, float] = {}

    def benchmark(self, name: str, func, iterations: int = 1000) -> float:
        """Benchmark a function over multiple iterations.

        Args:
            name: Benchmark name
            func: Function to benchmark
            iterations: Number of iterations

        Returns:
            Average time per iteration in milliseconds
        """
        start = time.time()
        for _ in range(iterations):
            func()
        elapsed = (time.time() - start) * 1000  # Convert to ms

        avg_time = elapsed / iterations
        self.results[name] = avg_time
        return avg_time

    def save_baseline(self, filepath: Path) -> None:
        """Save benchmark results as baseline.

        Args:
            filepath: Path to save baseline JSON
        """
        baseline = {
            "version": "1.0.0",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "benchmarks": self.results,
        }

        with filepath.open("w") as f:
            json.dump(baseline, f, indent=2)

    def compare_to_baseline(self, filepath: Path) -> dict[str, dict[str, float]]:
        """Compare current results to baseline.

        Args:
            filepath: Path to baseline JSON

        Returns:
            Dictionary of comparisons with regression info
        """
        if not filepath.exists():
            return {}

        with filepath.open("r") as f:
            baseline = json.load(f)

        comparisons = {}
        for name, current_time in self.results.items():
            baseline_time = baseline["benchmarks"].get(name)
            if baseline_time:
                regression = (current_time - baseline_time) / baseline_time * 100
                comparisons[name] = {
                    "baseline": baseline_time,
                    "current": current_time,
                    "regression_pct": regression,
                }

        return comparisons


@pytest.fixture
def benchmark():
    """Benchmark suite fixture."""
    return BenchmarkSuite()


def test_benchmark_empty_request(benchmark):
    """Benchmark empty request (baseline overhead)."""
    waf = WAF({"rules": []})

    def empty_request():
        tx = waf.new_transaction()
        tx.process_uri("/test", "GET")
        tx.process_request_body()

    avg_time = benchmark.benchmark("empty_request_ms", empty_request)
    print(f"\nEmpty request: {avg_time:.3f}ms")

    # Should be very fast (<1ms)
    assert avg_time < 1.0


def test_benchmark_simple_get_with_rules(benchmark):
    """Benchmark simple GET request with 5 rules."""
    waf = WAF({
        "rules": [
            'SecRule REQUEST_URI "@rx /admin" "id:1,phase:1,deny"',
            'SecRule ARGS "@rx attack" "id:2,phase:2,deny"',
            'SecRule REQUEST_HEADERS:User-Agent "@rx bot" "id:3,phase:1,deny"',
            'SecRule ARGS "@rx <script" "id:4,phase:2,deny"',
            'SecRule REQUEST_METHOD "@rx POST" "id:5,phase:1,deny"',
        ]
    })

    def simple_get():
        tx = waf.new_transaction()
        tx.process_uri("/api/users?id=123", "GET")
        tx.process_request_headers()
        tx.process_request_body()

    avg_time = benchmark.benchmark("simple_get_5_rules_ms", simple_get)
    print(f"\nSimple GET with 5 rules: {avg_time:.3f}ms")

    # Should still be fast (<5ms)
    assert avg_time < 5.0


def test_benchmark_json_parsing_1kb(benchmark):
    """Benchmark JSON body parsing (1KB)."""
    waf = WAF({"rules": []})
    body = b'{"user": {"id": 123, "name": "test", "data": "' + (b"x" * 800) + b'"}}'

    def parse_json():
        tx = waf.new_transaction()
        tx.process_uri("/api/data", "POST")
        tx.add_request_body(body, "application/json")
        tx.process_request_body()

    avg_time = benchmark.benchmark("json_1kb_ms", parse_json)
    print(f"\nJSON 1KB parsing: {avg_time:.3f}ms")

    # Should be fast (<2ms)
    assert avg_time < 2.0


def test_benchmark_json_parsing_100kb(benchmark):
    """Benchmark JSON body parsing (100KB)."""
    waf = WAF({"rules": []})
    # Create larger JSON (~100KB)
    items = []
    for i in range(500):
        items.append(f'{{"id": {i}, "name": "item{i}", "data": "{"x" * 100}"}}')
    body = b'{"items": [' + ",".join(items).encode() + b"]}"

    def parse_json():
        tx = waf.new_transaction()
        tx.process_uri("/api/data", "POST")
        tx.add_request_body(body, "application/json")
        tx.process_request_body()

    avg_time = benchmark.benchmark("json_100kb_ms", parse_json, iterations=100)
    print(f"\nJSON 100KB parsing: {avg_time:.3f}ms")

    # Should be reasonable (<10ms)
    assert avg_time < 10.0


def test_benchmark_xml_parsing(benchmark):
    """Benchmark XML body parsing."""
    waf = WAF({"rules": []})
    body = b"<root><user><id>123</id><name>test</name></user></root>"

    def parse_xml():
        tx = waf.new_transaction()
        tx.process_uri("/api/data", "POST")
        tx.add_request_body(body, "text/xml")
        tx.process_request_body()

    avg_time = benchmark.benchmark("xml_parsing_ms", parse_xml)
    print(f"\nXML parsing: {avg_time:.3f}ms")

    # Should be fast (<2ms)
    assert avg_time < 2.0


def test_benchmark_regex_operator(benchmark):
    """Benchmark regex operator performance."""
    options = OperatorOptions("(?i:select.*from)")
    operator = get_operator("rx", options)

    def match_regex():
        operator.evaluate(None, "SELECT * FROM users")

    avg_time = benchmark.benchmark("regex_operator_us", match_regex) * 1000  # to µs
    print(f"\nRegex operator: {avg_time:.1f}µs")

    # Should be very fast (<100µs)
    assert avg_time < 100


def test_benchmark_transformation_lowercase(benchmark):
    """Benchmark transformation performance."""

    def apply_transform():
        transformations.lowercase("HELLO WORLD")

    avg_time = benchmark.benchmark("transform_lowercase_us", apply_transform) * 1000
    print(f"\nLowercase transformation: {avg_time:.1f}µs")

    # Should be extremely fast (<20µs)
    assert avg_time < 20


@pytest.mark.skip(reason="Failing intermittently, needs investigation")
def test_benchmark_rule_evaluation_scaling():
    """Test rule evaluation performance scaling."""
    rule_counts = [10, 50, 100, 500]
    results = {}

    for count in rule_counts:
        rules = [
            f'SecRule ARGS "@rx pattern{i}" "id:{i},phase:2,log"' for i in range(count)
        ]
        waf = WAF({"rules": rules})

        start = time.time()
        iterations = 100

        for _ in range(iterations):
            tx = waf.new_transaction()
            tx.process_uri("/test?param=value", "GET")
            tx.process_request_body()

        elapsed = (time.time() - start) * 1000 / iterations
        results[count] = elapsed

        print(f"\n{count} rules: {elapsed:.3f}ms")

    # Verify scaling is reasonable (should be sub-linear due to early termination)
    # 500 rules should not be 50x slower than 10 rules
    assert results[500] / results[10] < 30


def test_benchmark_response_processing(benchmark):
    """Benchmark response processing (Phase 3-4)."""
    waf = WAF({
        "rules": [
            'SecRule RESPONSE_BODY "@rx password" "id:1,phase:4,deny"',
        ]
    })

    body = b'{"status": "success", "data": [1, 2, 3]}'

    def process_response():
        tx = waf.new_transaction()
        tx.process_uri("/api/data", "GET")
        tx.add_response_status(200)
        tx.add_response_body(body, "application/json")
        tx.process_response_body()

    avg_time = benchmark.benchmark("response_1kb_ms", process_response)
    print(f"\nResponse processing (1KB): {avg_time:.3f}ms")

    # Should be fast (<2ms)
    assert avg_time < 2.0


def test_benchmark_urlencoded_parsing(benchmark):
    """Benchmark URL-encoded body parsing."""
    waf = WAF({"rules": []})
    body = b"username=admin&password=secret123&action=login&token=abc123&data=" + (
        b"x" * 500
    )

    def parse_urlencoded():
        tx = waf.new_transaction()
        tx.process_uri("/login", "POST")
        tx.add_request_body(body, "application/x-www-form-urlencoded")
        tx.process_request_body()

    avg_time = benchmark.benchmark("urlencoded_parsing_ms", parse_urlencoded)
    print(f"\nURL-encoded parsing: {avg_time:.3f}ms")

    # Should be very fast (<1ms)
    assert avg_time < 1.0


def test_benchmark_multipart_parsing(benchmark):
    """Benchmark multipart form data parsing."""
    waf = WAF({"rules": []})
    boundary = "----WebKitFormBoundary"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="username"\r\n'
        b"\r\n"
        b"admin\r\n"
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"file content here\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    def parse_multipart():
        tx = waf.new_transaction()
        tx.process_uri("/upload", "POST")
        tx.add_request_body(body, f"multipart/form-data; boundary={boundary}")
        tx.process_request_body()

    avg_time = benchmark.benchmark("multipart_parsing_ms", parse_multipart)
    print(f"\nMultipart parsing: {avg_time:.3f}ms")

    # Should be reasonable (<3ms)
    assert avg_time < 3.0


def test_benchmark_concurrent_transactions():
    """Benchmark concurrent transaction handling."""
    waf = WAF({
        "rules": [
            'SecRule ARGS "@rx attack" "id:1,phase:2,deny"',
        ]
    })

    start = time.time()
    iterations = 1000

    # Simulate multiple transactions
    for i in range(iterations):
        tx = waf.new_transaction()
        tx.process_uri(f"/api/endpoint?id={i}", "GET")
        tx.process_request_body()

    elapsed = (time.time() - start) * 1000 / iterations
    print(f"\nConcurrent transactions: {elapsed:.3f}ms per transaction")

    # Should handle many transactions efficiently
    assert elapsed < 1.0


def test_benchmark_summary(benchmark):
    """Print benchmark summary."""
    print("\n=== Benchmark Summary ===")
    for name, time_ms in sorted(benchmark.results.items()):
        print(f"{name}: {time_ms:.4f}ms")


def test_save_baseline(benchmark, tmp_path):
    """Save benchmark baseline for regression detection."""
    # Run a few benchmarks
    waf = WAF({"rules": []})

    benchmark.benchmark(
        "test_empty", lambda: waf.new_transaction().process_request_body()
    )

    # Save baseline
    baseline_path = tmp_path / "baseline.json"
    benchmark.save_baseline(baseline_path)

    assert baseline_path.exists()

    # Verify format
    with baseline_path.open("r") as f:
        data = json.load(f)

    assert "version" in data
    assert "timestamp" in data
    assert "benchmarks" in data
    assert "test_empty" in data["benchmarks"]
