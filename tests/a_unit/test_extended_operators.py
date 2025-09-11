"""Tests for extended operators matching Go Coraza functionality."""

from __future__ import annotations

import pytest

from coraza_poc.primitives.operators import (
    BeginsWithOperator,
    DetectSQLiOperator,
    DetectXSSOperator,
    EndsWithOperator,
    GeOperator,
    GtOperator,
    IpMatchOperator,
    LeOperator,
    LtOperator,
    OperatorOptions,
    ValidateByteRangeOperator,
    ValidateUtf8EncodingOperator,
    WithinOperator,
    get_operator,
)


class MockTransaction:
    """Mock transaction for testing."""

    def __init__(self):
        self._capturing = False
        self._captures = {}

    def capturing(self) -> bool:
        return self._capturing

    def capture_field(self, index: int, value: str) -> None:
        self._captures[index] = value


def test_beginswith_operator():
    """Test begins with operator."""
    op = BeginsWithOperator("test")
    tx = MockTransaction()

    assert op.evaluate(tx, "testing") is True
    assert op.evaluate(tx, "test") is True
    assert op.evaluate(tx, "nottest") is False
    assert op.evaluate(tx, "") is False


def test_endswith_operator():
    """Test ends with operator."""
    op = EndsWithOperator("test")
    tx = MockTransaction()

    assert op.evaluate(tx, "mytest") is True
    assert op.evaluate(tx, "test") is True
    assert op.evaluate(tx, "testing") is False
    assert op.evaluate(tx, "") is False


def test_comparison_operators():
    """Test numerical comparison operators."""
    tx = MockTransaction()

    # Greater than
    gt_op = GtOperator("10")
    assert gt_op.evaluate(tx, "15") is True
    assert gt_op.evaluate(tx, "10") is False
    assert gt_op.evaluate(tx, "5") is False
    assert gt_op.evaluate(tx, "not_a_number") is False

    # Greater than or equal
    ge_op = GeOperator("10")
    assert ge_op.evaluate(tx, "15") is True
    assert ge_op.evaluate(tx, "10") is True
    assert ge_op.evaluate(tx, "5") is False

    # Less than
    lt_op = LtOperator("10")
    assert lt_op.evaluate(tx, "5") is True
    assert lt_op.evaluate(tx, "10") is False
    assert lt_op.evaluate(tx, "15") is False

    # Less than or equal
    le_op = LeOperator("10")
    assert le_op.evaluate(tx, "5") is True
    assert le_op.evaluate(tx, "10") is True
    assert le_op.evaluate(tx, "15") is False


def test_within_operator():
    """Test within operator."""
    op = WithinOperator("GET POST PUT")
    tx = MockTransaction()

    assert op.evaluate(tx, "GET") is True
    assert op.evaluate(tx, "POST") is True
    assert op.evaluate(tx, "PUT") is True
    assert op.evaluate(tx, "DELETE") is False
    assert op.evaluate(tx, "PATCH") is False


def test_ipmatch_operator():
    """Test IP matching operator."""
    tx = MockTransaction()

    # Exact IP match
    ip_op = IpMatchOperator("192.168.1.1")
    assert ip_op.evaluate(tx, "192.168.1.1") is True
    assert ip_op.evaluate(tx, "192.168.1.2") is False

    # CIDR network match
    cidr_op = IpMatchOperator("192.168.1.0/24")
    assert cidr_op.evaluate(tx, "192.168.1.1") is True
    assert cidr_op.evaluate(tx, "192.168.1.255") is True
    assert cidr_op.evaluate(tx, "192.168.2.1") is False

    # Invalid IP
    assert ip_op.evaluate(tx, "not_an_ip") is False


def test_detect_sqli_operator():
    """Test SQL injection detection operator."""
    op = DetectSQLiOperator("")
    tx = MockTransaction()

    # Common SQL injection patterns
    assert op.evaluate(tx, "1 OR 1=1") is True
    assert op.evaluate(tx, "UNION SELECT * FROM users") is True
    assert op.evaluate(tx, "DROP TABLE users") is True
    assert op.evaluate(tx, "'; DELETE FROM users; --") is True
    assert op.evaluate(tx, "1 AND 1=1") is True
    assert op.evaluate(tx, "exec(") is True

    # URL encoded SQL injection
    assert op.evaluate(tx, "1%20OR%201=1") is True

    # Normal input
    assert op.evaluate(tx, "normal input") is False
    assert op.evaluate(tx, "user@example.com") is False


def test_detect_xss_operator():
    """Test XSS detection operator."""
    op = DetectXSSOperator("")
    tx = MockTransaction()

    # Script tags
    assert op.evaluate(tx, "<script>alert('xss')</script>") is True
    assert op.evaluate(tx, "<SCRIPT>alert(1)</SCRIPT>") is True

    # JavaScript protocols
    assert op.evaluate(tx, "javascript:alert(1)") is True
    assert op.evaluate(tx, "JAVASCRIPT:alert(1)") is True

    # Event handlers
    assert op.evaluate(tx, "<img onload=alert(1)>") is True
    assert op.evaluate(tx, "<div onclick='alert(1)'>") is True

    # Other dangerous tags
    assert op.evaluate(tx, "<iframe src='javascript:alert(1)'></iframe>") is True
    assert op.evaluate(tx, "<object data='javascript:alert(1)'></object>") is True

    # Document manipulation
    assert op.evaluate(tx, "document.cookie") is True
    assert op.evaluate(tx, "eval('alert(1)')") is True

    # URL encoded XSS
    assert op.evaluate(tx, "%3Cscript%3Ealert(1)%3C/script%3E") is True

    # Normal input
    assert op.evaluate(tx, "normal text") is False
    assert op.evaluate(tx, "user@example.com") is False


def test_validate_byte_range_operator():
    """Test byte range validation operator."""
    tx = MockTransaction()

    # ASCII printable characters (32-126)
    ascii_op = ValidateByteRangeOperator("32-126")
    assert ascii_op.evaluate(tx, "Hello World!") is True
    assert ascii_op.evaluate(tx, "Test123") is True
    assert ascii_op.evaluate(tx, "Hello\x00World") is False  # null byte
    assert ascii_op.evaluate(tx, "Hello\x1fWorld") is False  # control character

    # Multiple ranges
    multi_op = ValidateByteRangeOperator("65-90,97-122")  # A-Z, a-z
    assert multi_op.evaluate(tx, "HelloWorld") is True
    assert multi_op.evaluate(tx, "Hello123") is False  # contains numbers

    # Single bytes
    single_op = ValidateByteRangeOperator("65,66,67")  # A, B, C
    assert single_op.evaluate(tx, "ABC") is True
    assert single_op.evaluate(tx, "ABCD") is False


def test_validate_utf8_encoding_operator():
    """Test UTF-8 encoding validation operator."""
    op = ValidateUtf8EncodingOperator("")
    tx = MockTransaction()

    # Valid UTF-8
    assert op.evaluate(tx, "Hello World") is True
    assert op.evaluate(tx, "café") is True
    assert op.evaluate(tx, "🚀") is True
    assert op.evaluate(tx, "日本語") is True

    # All valid UTF-8 strings should pass
    assert op.evaluate(tx, "") is True  # empty string
    assert op.evaluate(tx, "ASCII only") is True


def test_operator_factory_pattern():
    """Test that new operators work with the factory pattern."""
    # Test creating operators via factory
    options = OperatorOptions("test")

    op1 = get_operator("beginswith", options)
    assert isinstance(op1, BeginsWithOperator)

    op2 = get_operator("gt", OperatorOptions("10"))
    assert isinstance(op2, GtOperator)

    op3 = get_operator("detectsqli", options)
    assert isinstance(op3, DetectSQLiOperator)

    op4 = get_operator("detectxss", options)
    assert isinstance(op4, DetectXSSOperator)

    op5 = get_operator("ipmatch", OperatorOptions("192.168.1.0/24"))
    assert isinstance(op5, IpMatchOperator)


def test_operator_case_insensitivity():
    """Test that operator names are case insensitive."""
    options = OperatorOptions("test")

    op1 = get_operator("BEGINSWITH", options)
    op2 = get_operator("beginswith", options)
    op3 = get_operator("BeGiNsWiTh", options)

    assert type(op1) is type(op2) is type(op3)


def test_unknown_operator_error():
    """Test that unknown operators raise appropriate errors."""
    options = OperatorOptions("test")

    with pytest.raises(ValueError, match="Unknown operator"):
        get_operator("nonexistent", options)
