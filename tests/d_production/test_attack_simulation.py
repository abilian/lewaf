"""Real-world attack simulation tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from lewaf.integration import WAF


class AttackSimulator:
    """Simulate real-world attacks and measure detection."""

    def __init__(self, waf: WAF):
        self.waf = waf
        self.results: dict[str, dict[str, int]] = {}

    def simulate_attack(
        self, category: str, payloads: list[str], vector: str = "query"
    ) -> dict[str, int | float]:
        """Simulate attack with multiple payloads.

        Args:
            category: Attack category (e.g., "sqli", "xss")
            payloads: List of attack payloads
            vector: Attack vector ("query", "body", "header")

        Returns:
            Detection statistics
        """
        detected = 0
        total = len(payloads)

        for payload in payloads:
            tx = self.waf.new_transaction()

            if vector == "query":
                tx.process_uri(f"/test?param={payload}", "GET")
                result = tx.process_request_body()
            elif vector == "body":
                tx.process_uri("/test", "POST")
                body = f'{{"data": "{payload}"}}'
                tx.add_request_body(
                    body.encode("utf-8", errors="ignore"), "application/json"
                )
                result = tx.process_request_body()
            elif vector == "header":
                tx.process_uri("/test", "GET")
                tx.variables.request_headers.add("user-agent", payload)
                result = tx.process_request_headers()
            else:
                result = None

            if result is not None:
                detected += 1

        detection_rate = detected / total if total > 0 else 0.0
        self.results[category] = {
            "total": total,
            "detected": detected,
            "missed": total - detected,
        }

        return {
            "category": category,
            "total": total,
            "detected": detected,
            "missed": total - detected,
            "detection_rate": detection_rate,
        }

    def get_summary(self) -> dict[str, float | int]:
        """Get overall detection summary.

        Returns:
            Summary statistics
        """
        total_attacks = sum(r["total"] for r in self.results.values())
        total_detected = sum(r["detected"] for r in self.results.values())

        return {
            "total_attacks": total_attacks,
            "total_detected": total_detected,
            "total_missed": total_attacks - total_detected,
            "overall_detection_rate": (
                total_detected / total_attacks if total_attacks > 0 else 0.0
            ),
        }


@pytest.fixture
def comprehensive_waf():
    """WAF with comprehensive OWASP Top 10 rules."""
    return WAF({
        "rules": [
            # SQL Injection (A03:2021)
            'SecRule ARGS "@rx (?i:select.*from)" "id:1001,phase:2,deny,msg:\'SQL Injection\'"',
            'SecRule ARGS "@rx (?i:union.*select)" "id:1002,phase:2,deny,msg:\'SQL Injection\'"',
            'SecRule ARGS "@rx (?i:insert.*into)" "id:1003,phase:2,deny,msg:\'SQL Injection\'"',
            'SecRule REQUEST_BODY "@rx (?i:select.*from)" "id:1011,phase:2,deny,msg:\'SQL Injection in body\'"',
            # XSS (A03:2021)
            'SecRule ARGS "@rx <script" "id:2001,phase:2,deny,msg:\'XSS\'"',
            'SecRule ARGS "@rx (?i:onerror\\s*=)" "id:2002,phase:2,deny,msg:\'XSS\'"',
            'SecRule ARGS "@rx (?i:javascript:)" "id:2003,phase:2,deny,msg:\'XSS\'"',
            'SecRule REQUEST_BODY "@rx <script" "id:2011,phase:2,deny,msg:\'XSS in body\'"',
            # Path Traversal (A01:2021)
            'SecRule ARGS "@rx \\.\\./\\.\\." "id:3001,phase:2,deny,msg:\'Path Traversal\'"',
            'SecRule ARGS "@rx /etc/passwd" "id:3002,phase:2,deny,msg:\'File Access\'"',
            'SecRule REQUEST_URI "@rx \\.\\./\\.\\." "id:3011,phase:1,deny,msg:\'Path Traversal in URI\'"',
            # Command Injection (A03:2021)
            'SecRule ARGS "@rx (?i:;\\s*(?:cat|ls|whoami|id|pwd))" "id:4001,phase:2,deny,msg:\'Command Injection\'"',
            'SecRule ARGS "@rx (?i:\\|\\s*(?:cat|ls|whoami))" "id:4002,phase:2,deny,msg:\'Command Injection\'"',
            # Header Injection
            'SecRule REQUEST_HEADERS:User-Agent "@rx (?i:<script)" "id:5001,phase:1,deny,msg:\'Header XSS\'"',
            'SecRule REQUEST_HEADERS "@rx (?i:\\r\\n)" "id:5002,phase:1,deny,msg:\'CRLF Injection\'"',
        ]
    })


@pytest.fixture
def payloads_dir():
    """Get payloads directory path."""
    return Path(__file__).parent.parent / "fixtures" / "attack_payloads"


def test_simulate_sql_injection_attacks(comprehensive_waf, payloads_dir):
    """Simulate SQL injection attack campaign."""
    simulator = AttackSimulator(comprehensive_waf)

    # Load SQL injection payloads
    sqli_payloads = []
    with (payloads_dir / "sqli.txt").open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                sqli_payloads.append(line)

    # Simulate via query parameters
    result = simulator.simulate_attack("sqli_query", sqli_payloads[:20], vector="query")

    print("\nSQL Injection Attack Simulation:")
    print(f"  Total Attacks: {result['total']}")
    print(f"  Detected: {result['detected']}")
    print(f"  Missed: {result['missed']}")
    print(f"  Detection Rate: {result['detection_rate'] * 100:.1f}%")

    # Should detect reasonable portion
    assert result["detection_rate"] >= 0.30


def test_simulate_xss_attacks(comprehensive_waf, payloads_dir):
    """Simulate XSS attack campaign."""
    simulator = AttackSimulator(comprehensive_waf)

    # Load XSS payloads
    xss_payloads = []
    with (payloads_dir / "xss.txt").open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                xss_payloads.append(line)

    # Simulate via query parameters
    result = simulator.simulate_attack("xss_query", xss_payloads[:25], vector="query")

    print("\nXSS Attack Simulation:")
    print(f"  Total Attacks: {result['total']}")
    print(f"  Detected: {result['detected']}")
    print(f"  Missed: {result['missed']}")
    print(f"  Detection Rate: {result['detection_rate'] * 100:.1f}%")

    # Should detect good portion
    assert result["detection_rate"] >= 0.50


def test_simulate_path_traversal_attacks(comprehensive_waf, payloads_dir):
    """Simulate path traversal attack campaign."""
    simulator = AttackSimulator(comprehensive_waf)

    # Load LFI payloads
    lfi_payloads = []
    with (payloads_dir / "lfi.txt").open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                lfi_payloads.append(line)

    # Simulate via query parameters
    result = simulator.simulate_attack("lfi_query", lfi_payloads[:20], vector="query")

    print("\nPath Traversal Attack Simulation:")
    print(f"  Total Attacks: {result['total']}")
    print(f"  Detected: {result['detected']}")
    print(f"  Missed: {result['missed']}")
    print(f"  Detection Rate: {result['detection_rate'] * 100:.1f}%")

    # Many use encoding, so lower threshold
    assert result["detection_rate"] >= 0.25


def test_simulate_command_injection_attacks(comprehensive_waf):
    """Simulate command injection attacks."""
    simulator = AttackSimulator(comprehensive_waf)

    # Command injection payloads
    payloads = [
        "; cat /etc/passwd",
        "| ls -la",
        "; whoami",
        "& id",
        "; pwd",
        "| cat /etc/shadow",
        "; ls /",
        "| whoami",
        "; id",
        "| pwd",
        "&& cat /etc/passwd",
        "|| ls -la",
    ]

    result = simulator.simulate_attack("cmdi", payloads, vector="query")

    print("\nCommand Injection Attack Simulation:")
    print(f"  Total Attacks: {result['total']}")
    print(f"  Detected: {result['detected']}")
    print(f"  Missed: {result['missed']}")
    print(f"  Detection Rate: {result['detection_rate'] * 100:.1f}%")

    # Should detect most command injection
    assert result["detection_rate"] >= 0.50


def test_simulate_header_injection_attacks(comprehensive_waf):
    """Simulate header injection attacks."""
    simulator = AttackSimulator(comprehensive_waf)

    # Header injection payloads
    payloads = [
        "<script>alert(1)</script>",
        "test\r\nX-Injected: header",
        "Mozilla/5.0 <script>alert(1)</script>",
        "test\nSet-Cookie: injected=true",
        "test\r\nLocation: http://evil.com",
    ]

    result = simulator.simulate_attack("header_injection", payloads, vector="header")

    print("\nHeader Injection Attack Simulation:")
    print(f"  Total Attacks: {result['total']}")
    print(f"  Detected: {result['detected']}")
    print(f"  Missed: {result['missed']}")
    print(f"  Detection Rate: {result['detection_rate'] * 100:.1f}%")

    # Should detect some header attacks
    assert result["detection_rate"] >= 0.20


def test_simulate_multi_vector_attack():
    """Simulate attack across multiple vectors."""
    waf = WAF({
        "rules": [
            'SecRule ARGS "@rx (?i:attack)" "id:1,phase:2,deny"',
            'SecRule REQUEST_BODY "@rx (?i:attack)" "id:2,phase:2,deny"',
            'SecRule REQUEST_HEADERS:User-Agent "@rx (?i:attack)" "id:3,phase:1,deny"',
        ]
    })

    simulator = AttackSimulator(waf)

    # Same payload across different vectors
    payload = "attack_payload"

    # Test query vector
    result1 = simulator.simulate_attack("query", [payload], vector="query")
    assert result1["detection_rate"] == 1.0

    # Test body vector
    result2 = simulator.simulate_attack("body", [payload], vector="body")
    assert result2["detection_rate"] == 1.0

    # Test header vector
    result3 = simulator.simulate_attack("header", [payload], vector="header")
    assert result3["detection_rate"] == 1.0


def test_simulate_owasp_top10_campaign(comprehensive_waf, payloads_dir):
    """Simulate comprehensive OWASP Top 10 attack campaign."""
    simulator = AttackSimulator(comprehensive_waf)

    # Load all payloads
    sqli_file = payloads_dir / "sqli.txt"
    xss_file = payloads_dir / "xss.txt"
    lfi_file = payloads_dir / "lfi.txt"

    all_payloads = []
    for file in [sqli_file, xss_file, lfi_file]:
        if file.exists():
            with file.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        all_payloads.append(line)

    # Take sample from each
    result = simulator.simulate_attack("owasp_top10", all_payloads[:50], vector="query")

    print("\nOWSAP Top 10 Campaign Simulation:")
    print(f"  Total Attacks: {result['total']}")
    print(f"  Detected: {result['detected']}")
    print(f"  Missed: {result['missed']}")
    print(f"  Detection Rate: {result['detection_rate'] * 100:.1f}%")

    # Mixed attacks, lower threshold
    assert result["detection_rate"] >= 0.40


def test_simulate_evasion_techniques():
    """Test detection of evasion techniques."""
    waf = WAF({
        "rules": [
            'SecRule ARGS "@rx (?i:select.*from)" "id:1,phase:2,deny"',
            'SecRule ARGS "@rx <script" "id:2,phase:2,deny"',
        ]
    })

    simulator = AttackSimulator(waf)

    # Evasion attempts
    evasion_payloads = [
        # Case variations
        "SeLeCt * FrOm users",
        "<ScRiPt>alert(1)</ScRiPt>",
        # Comment-based
        "SELECT/**/FROM",
        "<script>/**/alert(1)</script>",
        # Whitespace variations
        "SELECT  \t  FROM",
        # Concatenation
        "SEL" + "ECT * FR" + "OM users",
    ]

    result = simulator.simulate_attack("evasion", evasion_payloads, vector="query")

    print("\nEvasion Technique Detection:")
    print(f"  Total Attempts: {result['total']}")
    print(f"  Detected: {result['detected']}")
    print(f"  Missed: {result['missed']}")
    print(f"  Detection Rate: {result['detection_rate'] * 100:.1f}%")

    # Case-insensitive regex should catch most
    assert result["detection_rate"] >= 0.50


def test_simulate_attack_chaining():
    """Test detection of chained attacks."""
    waf = WAF({
        "rules": [
            'SecRule ARGS "@rx (?i:select)" "id:1,phase:2,deny"',
            'SecRule ARGS "@rx (?i:<script)" "id:2,phase:2,deny"',
            'SecRule ARGS "@rx (?i:\\.\\.)" "id:3,phase:2,deny"',
        ]
    })

    # Chained attack attempts
    tx1 = waf.new_transaction()
    tx1.process_uri("/test?param=SELECT * FROM users; <script>alert(1)</script>", "GET")
    result1 = tx1.process_request_body()

    # Should detect first attack in chain
    assert result1 is not None

    # Second attack attempt
    tx2 = waf.new_transaction()
    tx2.process_uri("/test?file=../../etc/passwd&xss=<script>alert(1)</script>", "GET")
    result2 = tx2.process_request_body()

    # Should detect one of the attacks
    assert result2 is not None


def test_attack_detection_rates_summary(comprehensive_waf, payloads_dir):
    """Generate comprehensive attack detection rate summary."""
    simulator = AttackSimulator(comprehensive_waf)

    # Simulate multiple attack categories
    categories = []

    # SQL injection
    sqli_payloads = []
    with (payloads_dir / "sqli.txt").open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                sqli_payloads.append(line)
    if sqli_payloads:
        simulator.simulate_attack("sqli", sqli_payloads[:15], vector="query")
        categories.append("sqli")

    # XSS
    xss_payloads = []
    with (payloads_dir / "xss.txt").open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                xss_payloads.append(line)
    if xss_payloads:
        simulator.simulate_attack("xss", xss_payloads[:15], vector="query")
        categories.append("xss")

    # Get summary
    summary = simulator.get_summary()

    print("\n=== Attack Detection Summary ===")
    print(f"Total Attacks Simulated: {summary['total_attacks']}")
    print(f"Total Detected: {summary['total_detected']}")
    print(f"Total Missed: {summary['total_missed']}")
    print(f"Overall Detection Rate: {summary['overall_detection_rate'] * 100:.1f}%")

    print("\nBy Category:")
    for category in categories:
        if category in simulator.results:
            stats = simulator.results[category]
            rate = stats["detected"] / stats["total"] * 100 if stats["total"] > 0 else 0
            print(f"  {category}: {stats['detected']}/{stats['total']} ({rate:.1f}%)")

    # Should have reasonable overall detection
    assert summary["overall_detection_rate"] >= 0.35


def test_simulate_real_world_attack_scenario():
    """Simulate realistic attack scenario."""
    waf = WAF({
        "rules": [
            'SecRule ARGS "@rx (?i:union.*select)" "id:1,phase:2,deny"',
            'SecRule REQUEST_BODY "@rx (?i:password)" "id:2,phase:2,deny"',
        ]
    })

    # Scenario: Attacker tries SQL injection in login form
    tx1 = waf.new_transaction()
    tx1.process_uri("/login", "POST")
    payload1 = '{"username": "admin", "password": "test\' UNION SELECT * FROM users--"}'
    tx1.add_request_body(payload1.encode(), "application/json")
    result1 = tx1.process_request_body()

    # Should detect either SQL injection or password in response
    assert result1 is not None

    # Scenario: Attacker tries to extract data
    tx2 = waf.new_transaction()
    tx2.process_uri("/api/users?id=1 UNION SELECT password FROM admin", "GET")
    result2 = tx2.process_request_body()

    # Should detect SQL injection in query
    assert result2 is not None


def test_performance_under_attack_load():
    """Test WAF performance under sustained attack."""
    waf = WAF({
        "rules": [
            'SecRule ARGS "@rx (?i:attack)" "id:1,phase:2,deny"',
        ]
    })

    import time

    # Simulate rapid attack attempts
    start = time.time()
    attack_count = 100

    blocked = 0
    for i in range(attack_count):
        tx = waf.new_transaction()
        tx.process_uri(f"/test?param=attack_{i}", "GET")
        result = tx.process_request_body()
        if result:
            blocked += 1

    elapsed = time.time() - start

    print("\nPerformance Under Attack:")
    print(f"  Attacks: {attack_count}")
    print(f"  Blocked: {blocked}")
    print(f"  Time: {elapsed:.2f}s")
    print(f"  Rate: {attack_count / elapsed:.1f} attacks/sec")

    # Should block all attacks quickly
    assert blocked == attack_count
    assert elapsed < 5.0  # Should handle 100 attacks in <5 seconds
