"""Unit tests for security-focused operators (detectXSS, detectSQLi, etc.)."""

from __future__ import annotations

from lewaf.primitives.operators import OperatorOptions, get_operator
from tests.utils import stub_tx


def test_detect_xss_operator():
    """Test XSS detection operator."""
    options = OperatorOptions("")
    operator = get_operator("detectxss", options)

    tx = stub_tx()

    # Basic XSS patterns
    assert operator.evaluate(tx, "<script>alert(1)</script>") is True
    assert operator.evaluate(tx, "<img src=x onerror=alert(1)>") is True
    assert operator.evaluate(tx, "javascript:alert(1)") is True

    # Non-XSS content
    assert operator.evaluate(tx, "normal text") is False
    assert operator.evaluate(tx, "<p>Safe HTML</p>") is False
    assert operator.evaluate(tx, "user@example.com") is False


def test_detect_sqli_operator():
    """Test SQL injection detection operator."""
    options = OperatorOptions("")
    operator = get_operator("detectsqli", options)

    tx = stub_tx()

    # Basic SQLi patterns
    assert operator.evaluate(tx, "' OR 1=1--") is True
    assert operator.evaluate(tx, "'; DROP TABLE users;--") is True
    assert operator.evaluate(tx, "1' UNION SELECT * FROM passwords--") is True

    # Non-SQLi content
    assert operator.evaluate(tx, "normal text") is False
    assert operator.evaluate(tx, "user@example.com") is False
    assert operator.evaluate(tx, "regular query") is False


def test_ipmatch_operator():
    """Test IP address matching operator."""
    options = OperatorOptions("192.168.1.0/24")
    operator = get_operator("ipmatch", options)

    tx = stub_tx()

    # IPs in range
    assert operator.evaluate(tx, "192.168.1.1") is True
    assert operator.evaluate(tx, "192.168.1.100") is True
    assert operator.evaluate(tx, "192.168.1.254") is True

    # IPs outside range
    assert operator.evaluate(tx, "192.168.2.1") is False
    assert operator.evaluate(tx, "10.0.0.1") is False
    assert operator.evaluate(tx, "invalid_ip") is False


def test_ipmatch_single_ip():
    """Test IP matching for single IP address."""
    options = OperatorOptions("10.0.0.1")
    operator = get_operator("ipmatch", options)

    tx = stub_tx()

    assert operator.evaluate(tx, "10.0.0.1") is True
    assert operator.evaluate(tx, "10.0.0.2") is False
    assert operator.evaluate(tx, "192.168.1.1") is False


def test_validate_byte_range_operator():
    """Test byte range validation operator."""
    options = OperatorOptions("32-126")  # Printable ASCII range
    operator = get_operator("validatebyterange", options)

    tx = stub_tx()

    # Valid ASCII characters
    assert operator.evaluate(tx, "Hello World!") is True
    assert operator.evaluate(tx, "123 ABC xyz") is True

    # Invalid characters (outside range)
    assert operator.evaluate(tx, "Hello\x00World") is False
    assert operator.evaluate(tx, "Test\x01\x02") is False


def test_validate_utf8_encoding_operator():
    """Test UTF-8 encoding validation operator."""
    options = OperatorOptions("")
    operator = get_operator("validateutf8encoding", options)

    tx = stub_tx()

    # Valid UTF-8
    assert operator.evaluate(tx, "Hello World") is True
    assert operator.evaluate(tx, "Café résumé") is True
    assert operator.evaluate(tx, "测试文本") is True

    # Invalid UTF-8 is harder to test without binary data
    assert operator.evaluate(tx, "normal text") is True


def test_validate_url_encoding_operator():
    """Test URL encoding validation operator (detects invalid encoding)."""
    options = OperatorOptions("")
    operator = get_operator("validateurlencoding", options)

    tx = stub_tx()

    # Valid URL encoding (should return False - no invalid encoding found)
    assert operator.evaluate(tx, "hello%20world") is False
    assert operator.evaluate(tx, "test%3Dvalue") is False
    assert operator.evaluate(tx, "normal_text") is False

    # Invalid URL encoding (should return True - invalid encoding detected)
    assert operator.evaluate(tx, "test%2") is True  # Incomplete encoding
    assert operator.evaluate(tx, "test%ZZ") is True  # Invalid hex


def test_validate_schema_operator():
    """Test schema validation operator (detects invalid JSON/XML)."""
    options = OperatorOptions(
        '{"type": "object", "properties": {"name": {"type": "string"}}}'
    )
    operator = get_operator("validateschema", options)

    tx = stub_tx()

    # Valid JSON (should return False - no validation error)
    assert operator.evaluate(tx, '{"name": "test"}') is False

    # Invalid JSON (should return True - validation failed)
    assert (
        operator.evaluate(tx, '{"age": 25}') is False
    )  # Still valid JSON, just different schema
    assert operator.evaluate(tx, "invalid json") is True


def test_nomatch_operator():
    """Test nomatch operator (always returns False)."""
    options = OperatorOptions("anything")
    operator = get_operator("nomatch", options)

    tx = stub_tx()

    # Should always return False regardless of input
    assert operator.evaluate(tx, "anything") is False
    assert operator.evaluate(tx, "") is False
    assert operator.evaluate(tx, "test") is False


def test_restpath_operator():
    """Test REST path validation operator."""
    options = OperatorOptions("/api/users/{id}/posts/{post_id}")
    operator = get_operator("restpath", options)

    tx = stub_tx()

    # Valid REST paths
    assert operator.evaluate(tx, "/api/users/123/posts/456") is True
    assert operator.evaluate(tx, "/api/users/abc/posts/xyz") is True

    # Invalid REST paths
    assert operator.evaluate(tx, "/api/users/123") is False  # Incomplete
    assert operator.evaluate(tx, "/other/path") is False  # Different pattern
