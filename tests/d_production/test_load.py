"""Load testing for production readiness validation."""

from __future__ import annotations

import pytest

from lewaf.integration import WAF
from tests.utils.traffic_generator import TrafficGenerator


@pytest.fixture
def waf_basic():
    """Create WAF with basic rules for load testing."""
    return WAF({
        "rules": [
            'SecRule ARGS "@rx (?i:select.*from)" "id:100,phase:2,deny,msg:\'SQL Injection\'"',
            'SecRule REQUEST_HEADERS:User-Agent "@rx (?i:bot)" "id:101,phase:1,deny,msg:\'Bot Detected\'"',
            'SecRule REQUEST_URI "@rx \\.\\./" "id:102,phase:1,deny,msg:\'Path Traversal\'"',
        ]
    })


@pytest.fixture
def waf_heavy():
    """Create WAF with many rules for stress testing."""
    rules = []
    # Create 50 rules to simulate real-world CRS deployment
    for i in range(50):
        rules.append(
            f'SecRule ARGS "@rx pattern{i}" "id:{200 + i},phase:2,log,msg:\'Test Rule {i}\'"'
        )
    return WAF({"rules": rules})


def test_load_100_requests(waf_basic):
    """Test WAF handles 100 concurrent requests."""
    generator = TrafficGenerator(waf_basic, concurrency=10)
    metrics = generator.run(total_requests=100)

    # Verify all requests processed
    assert metrics["total_requests"] == 100

    # Verify error rate acceptable
    assert metrics["error_rate"] < 0.01  # <1% errors

    # Verify latency reasonable
    assert metrics["latency_p95"] < 50  # P95 < 50ms
    assert metrics["latency_p99"] < 100  # P99 < 100ms


def test_load_500_requests(waf_basic):
    """Test WAF handles 500 concurrent requests."""
    generator = TrafficGenerator(waf_basic, concurrency=20)
    metrics = generator.run(total_requests=500)

    assert metrics["total_requests"] == 500
    assert metrics["error_rate"] < 0.01
    assert metrics["latency_p95"] < 50
    assert metrics["latency_p99"] < 100


def test_load_1000_requests(waf_basic):
    """Test WAF handles 1000 concurrent requests."""
    generator = TrafficGenerator(waf_basic, concurrency=50)
    metrics = generator.run(total_requests=1000)

    assert metrics["total_requests"] == 1000
    assert metrics["error_rate"] < 0.01
    assert metrics["latency_p95"] < 100  # Slightly higher threshold
    assert metrics["latency_p99"] < 200


def test_load_duration_10_seconds(waf_basic):
    """Test WAF stability over 10 second duration."""
    generator = TrafficGenerator(waf_basic, concurrency=20)
    metrics = generator.run(duration_sec=10)

    # Should process many requests in 10 seconds
    assert metrics["total_requests"] > 100
    assert metrics["duration_sec"] >= 10
    assert metrics["duration_sec"] < 12  # Allow small overhead

    # Check throughput reasonable
    assert metrics["throughput_rps"] > 10  # At least 10 req/sec

    # Check stability (error rate)
    assert metrics["error_rate"] < 0.01


def test_load_with_heavy_ruleset(waf_heavy):
    """Test WAF performance with many rules."""
    generator = TrafficGenerator(waf_heavy, concurrency=10)
    metrics = generator.run(total_requests=200)

    assert metrics["total_requests"] == 200
    assert metrics["error_rate"] < 0.01

    # Latency may be higher with more rules
    assert metrics["latency_p95"] < 200  # More lenient threshold
    assert metrics["latency_p99"] < 500


def test_load_empty_waf():
    """Test WAF with no rules (baseline overhead)."""
    waf = WAF({"rules": []})
    generator = TrafficGenerator(waf, concurrency=10)
    metrics = generator.run(total_requests=500)

    assert metrics["total_requests"] == 500
    assert metrics["error_rate"] == 0.0  # No rules, no errors

    # Should be very fast with no rules
    assert metrics["latency_p95"] < 10  # <10ms P95
    assert metrics["latency_mean"] < 5  # <5ms mean


def test_load_throughput_measurement(waf_basic):
    """Measure throughput in requests per second."""
    generator = TrafficGenerator(waf_basic, concurrency=50)
    metrics = generator.run(duration_sec=5)

    # Check throughput calculation
    assert metrics["throughput_rps"] > 0
    expected_rps = metrics["total_requests"] / metrics["duration_sec"]
    assert abs(metrics["throughput_rps"] - expected_rps) < 1


def test_load_latency_percentiles(waf_basic):
    """Verify latency percentile calculations."""
    generator = TrafficGenerator(waf_basic, concurrency=10)
    metrics = generator.run(total_requests=100)

    # Verify percentiles ordered correctly
    assert metrics["latency_min"] <= metrics["latency_p50"]
    assert metrics["latency_p50"] <= metrics["latency_p95"]
    assert metrics["latency_p95"] <= metrics["latency_p99"]
    assert metrics["latency_p99"] <= metrics["latency_max"]

    # Verify mean and median reasonable
    assert metrics["latency_mean"] > 0
    assert metrics["latency_median"] > 0


def test_load_error_rate_calculation(waf_basic):
    """Verify error rate calculation."""
    generator = TrafficGenerator(waf_basic, concurrency=10)
    metrics = generator.run(total_requests=100)

    # Error rate should be errors / total
    expected_error_rate = metrics["error_count"] / metrics["total_requests"]
    assert metrics["error_rate"] == expected_error_rate


def test_load_concurrency_levels():
    """Test different concurrency levels."""
    waf = WAF({"rules": []})

    for concurrency in [1, 5, 10, 20, 50]:
        generator = TrafficGenerator(waf, concurrency=concurrency)
        metrics = generator.run(total_requests=100)

        assert metrics["total_requests"] == 100
        assert metrics["error_rate"] == 0.0


def test_load_request_distribution(waf_basic):
    """Test request method distribution is varied."""
    generator = TrafficGenerator(waf_basic, concurrency=10)

    # Generate 100 requests and track methods
    methods_seen = set()
    for _ in range(100):
        request = generator.generate_request()
        methods_seen.add(request["method"])

    # Should see variety of methods
    assert "GET" in methods_seen
    assert "POST" in methods_seen
    # May not see all methods in 100 requests, but should see variety


def test_load_metrics_summary_format(waf_basic):
    """Verify metrics summary contains expected fields."""
    generator = TrafficGenerator(waf_basic, concurrency=10)
    metrics = generator.run(total_requests=50)

    # Required fields
    required_fields = [
        "total_requests",
        "error_count",
        "error_rate",
        "latency_min",
        "latency_max",
        "latency_mean",
        "latency_median",
        "latency_p50",
        "latency_p95",
        "latency_p99",
        "throughput_rps",
        "duration_sec",
    ]

    for field in required_fields:
        assert field in metrics
        assert isinstance(metrics[field], (int, float))
