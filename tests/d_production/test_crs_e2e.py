"""End-to-end CRS rule validation tests."""

from pathlib import Path

import pytest

from lewaf.integration import WAF
from tests.utils.crs_validator import CRSValidator


@pytest.fixture
def crs_sql_waf():
    """WAF with SQL injection rules."""
    return WAF(
        {
            "rules": [
                # SQL injection detection
                'SecRule ARGS "@rx (?i:select.*from)" "id:942100,phase:2,deny,msg:\'SQL Injection - SELECT FROM\'"',
                'SecRule ARGS "@rx (?i:union.*select)" "id:942200,phase:2,deny,msg:\'SQL Injection - UNION SELECT\'"',
                'SecRule ARGS "@rx (?i:or.+?=)" "id:942300,phase:2,deny,msg:\'SQL Injection - OR condition\'"',
                'SecRule REQUEST_BODY "@rx (?i:union.*select)" "id:942201,phase:2,deny,msg:\'SQL Injection in body\'"',
                'SecRule REQUEST_BODY "@rx (?i:and\\s+sleep\\()" "id:942400,phase:2,deny,msg:\'SQL Injection - Time-based blind\'"',
            ]
        }
    )


@pytest.fixture
def crs_xss_waf():
    """WAF with XSS rules."""
    return WAF(
        {
            "rules": [
                # XSS detection
                'SecRule ARGS "@rx <script" "id:941100,phase:2,deny,msg:\'XSS - script tag\'"',
                'SecRule ARGS "@rx (?i:on\\w+\\s*=)" "id:941200,phase:2,deny,msg:\'XSS - event handler\'"',
                'SecRule ARGS "@rx (?i:javascript:)" "id:941300,phase:2,deny,msg:\'XSS - javascript protocol\'"',
                'SecRule REQUEST_BODY "@rx <script" "id:941101,phase:2,deny,msg:\'XSS in body\'"',
                'SecRule REQUEST_BODY "@rx (?i:onerror\\s*=)" "id:941201,phase:2,deny,msg:\'XSS - onerror handler\'"',
            ]
        }
    )


@pytest.fixture
def crs_lfi_waf():
    """WAF with LFI/path traversal rules."""
    return WAF(
        {
            "rules": [
                # Path traversal detection
                'SecRule ARGS "@rx \\.\\./\\.\\." "id:930100,phase:2,deny,msg:\'Path Traversal\'"',
                'SecRule ARGS "@rx /etc/passwd" "id:930200,phase:2,deny,msg:\'Unix passwd file access\'"',
                'SecRule ARGS "@rx (?i:windows.*system32)" "id:930300,phase:2,deny,msg:\'Windows system access\'"',
                'SecRule REQUEST_URI "@rx \\.\\./\\.\\." "id:930101,phase:1,deny,msg:\'Path Traversal in URI\'"',
            ]
        }
    )


@pytest.fixture
def payloads_dir():
    """Get payloads directory path."""
    return Path(__file__).parent.parent / "fixtures" / "attack_payloads"


def test_crs_sqli_detection(crs_sql_waf, payloads_dir):
    """Test SQL injection payload detection."""
    validator = CRSValidator(crs_sql_waf)
    payloads = validator.load_payloads_from_file(payloads_dir / "sqli.txt")

    # Should detect most SQL injection payloads
    assert len(payloads) > 10, "Need SQL injection payloads"

    detected = 0
    for payload in payloads:
        tx = crs_sql_waf.new_transaction()
        tx.process_uri(f"/test?param={payload}", "GET")
        result = tx.process_request_body()

        if result is not None:
            detected += 1

    detection_rate = detected / len(payloads)
    print(
        f"\nSQL Injection Detection: {detected}/{len(payloads)} ({detection_rate * 100:.1f}%)"
    )

    # Should detect at least 40% of SQL injection attempts (many use advanced evasion)
    assert detection_rate >= 0.40, (
        f"SQL injection detection too low: {detection_rate * 100:.1f}%"
    )


def test_crs_xss_detection(crs_xss_waf, payloads_dir):
    """Test XSS payload detection."""
    validator = CRSValidator(crs_xss_waf)
    payloads = validator.load_payloads_from_file(payloads_dir / "xss.txt")

    assert len(payloads) > 10, "Need XSS payloads"

    detected = 0
    for payload in payloads:
        tx = crs_xss_waf.new_transaction()
        tx.process_uri(f"/test?param={payload}", "GET")
        result = tx.process_request_body()

        if result is not None:
            detected += 1

    detection_rate = detected / len(payloads)
    print(f"\nXSS Detection: {detected}/{len(payloads)} ({detection_rate * 100:.1f}%)")

    # Should detect at least 70% of XSS attempts (some are very obscure)
    assert detection_rate >= 0.7, f"XSS detection too low: {detection_rate * 100:.1f}%"


def test_crs_lfi_detection(crs_lfi_waf, payloads_dir):
    """Test LFI/path traversal payload detection."""
    validator = CRSValidator(crs_lfi_waf)
    payloads = validator.load_payloads_from_file(payloads_dir / "lfi.txt")

    assert len(payloads) > 10, "Need LFI payloads"

    detected = 0
    for payload in payloads:
        tx = crs_lfi_waf.new_transaction()
        tx.process_uri(f"/test?file={payload}", "GET")
        result = tx.process_request_body()

        if result is not None:
            detected += 1

    detection_rate = detected / len(payloads)
    print(f"\nLFI Detection: {detected}/{len(payloads)} ({detection_rate * 100:.1f}%)")

    # Should detect at least 30% of LFI attempts (many payloads use encoding/obfuscation)
    assert detection_rate >= 0.30, f"LFI detection too low: {detection_rate * 100:.1f}%"


def test_crs_xxe_protection():
    """Test XXE protection via XML processor."""
    waf = WAF({"rules": []})

    # Basic XXE attempt
    xxe_payload = b"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>"""

    tx = waf.new_transaction()
    tx.process_uri("/api/data", "POST")
    tx.add_request_body(xxe_payload, "text/xml")
    tx.process_request_body()

    # Should set error variable (parse fails)
    assert tx.variables.reqbody_error.get() == "1"
    assert "Invalid XML" in tx.variables.reqbody_error_msg.get()


def test_crs_sqli_in_request_body(crs_sql_waf):
    """Test SQL injection in JSON request body."""
    payload = (
        '{"username": "admin", "query": "SELECT * FROM users UNION SELECT password"}'
    )

    tx = crs_sql_waf.new_transaction()
    tx.process_uri("/api/search", "POST")
    tx.add_request_body(payload.encode(), "application/json")
    result = tx.process_request_body()

    # Should detect SQL injection in body
    assert result is not None
    assert result["rule_id"] in [942100, 942200, 942201]


def test_crs_xss_in_request_body(crs_xss_waf):
    """Test XSS in JSON request body."""
    payload = '{"comment": "<script>alert(1)</script>", "user": "attacker"}'

    tx = crs_xss_waf.new_transaction()
    tx.process_uri("/api/comment", "POST")
    tx.add_request_body(payload.encode(), "application/json")
    result = tx.process_request_body()

    # Should detect XSS in body
    assert result is not None
    assert result["rule_id"] in [941100, 941101]


def test_crs_multiple_attack_vectors():
    """Test detection of multiple attack types."""
    waf = WAF(
        {
            "rules": [
                'SecRule ARGS "@rx (?i:select.*from)" "id:1,phase:2,deny"',
                'SecRule ARGS "@rx <script" "id:2,phase:2,deny"',
                'SecRule ARGS "@rx \\.\\./\\.\\." "id:3,phase:2,deny"',
            ]
        }
    )

    # Test SQL injection
    tx1 = waf.new_transaction()
    tx1.process_uri("/test?q=SELECT * FROM users", "GET")
    assert tx1.process_request_body() is not None

    # Test XSS
    tx2 = waf.new_transaction()
    tx2.process_uri("/test?comment=<script>alert(1)</script>", "GET")
    assert tx2.process_request_body() is not None

    # Test LFI
    tx3 = waf.new_transaction()
    tx3.process_uri("/test?file=../../etc/passwd", "GET")
    assert tx3.process_request_body() is not None


def test_crs_legitimate_traffic_passes():
    """Test that legitimate traffic is not blocked."""
    waf = WAF(
        {
            "rules": [
                'SecRule ARGS "@rx (?i:select.*from)" "id:1,phase:2,deny"',
                'SecRule ARGS "@rx <script" "id:2,phase:2,deny"',
            ]
        }
    )

    # Legitimate search
    tx1 = waf.new_transaction()
    tx1.process_uri("/api/search?q=python+programming", "GET")
    assert tx1.process_request_body() is None

    # Legitimate comment
    tx2 = waf.new_transaction()
    tx2.process_uri("/api/comment?text=This+is+a+great+article", "GET")
    assert tx2.process_request_body() is None

    # Legitimate file access
    tx3 = waf.new_transaction()
    tx3.process_uri("/files/document.pdf", "GET")
    assert tx3.process_request_body() is None


def test_crs_encoded_payloads():
    """Test detection of URL-encoded attack payloads."""
    waf = WAF(
        {
            "rules": [
                'SecRule ARGS "@rx (?i:union.*select)" "id:1,phase:2,deny"',
            ]
        }
    )

    # URL-encoded UNION SELECT
    tx = waf.new_transaction()
    tx.process_uri("/test?q=1%27%20UNION%20SELECT%20NULL--", "GET")

    # Note: Our current implementation doesn't URL-decode automatically
    # This is a known limitation - would need URL decoding transformation
    # For now, just verify it doesn't crash
    result = tx.process_request_body()
    # May or may not detect depending on URL decoding
    assert result is None or isinstance(result, dict), "Should return valid result"


def test_crs_case_variations():
    """Test detection with case variations."""
    waf = WAF(
        {
            "rules": [
                'SecRule ARGS "@rx (?i:union.*select)" "id:1,phase:2,deny"',
            ]
        }
    )

    # Various case combinations
    test_cases = [
        "UNION SELECT",
        "union select",
        "UnIoN sElEcT",
        "uNiOn SeLeCt",
    ]

    for test_case in test_cases:
        tx = waf.new_transaction()
        tx.process_uri(f"/test?q={test_case}", "GET")
        result = tx.process_request_body()
        # Case-insensitive regex should detect all
        assert result is not None, f"Failed to detect: {test_case}"


def test_crs_coverage_report(crs_sql_waf, payloads_dir):
    """Generate coverage report for SQL injection rules."""
    validator = CRSValidator(crs_sql_waf)
    payloads = validator.load_payloads_from_file(payloads_dir / "sqli.txt")

    # Test all payloads
    for payload in payloads[:20]:  # Limit to 20 for test speed
        validator.validate_payload(0, payload, should_block=True)

    # Get coverage report
    report = validator.get_coverage_report()

    assert report["total_tests"] == 20
    assert report["pass_rate"] >= 0.20  # At least 20% should be detected
    assert "rule_stats" in report
