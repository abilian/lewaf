"""Unit tests for basic operators (rx, eq, contains, etc.)."""

from __future__ import annotations

from lewaf.primitives.operators import OperatorOptions, get_operator


def test_rx_operator_basic_match():
    """Test basic regex operator functionality."""
    options = OperatorOptions(r"test.*pattern")
    operator = get_operator("rx", options)

    # Mock transaction (not needed for rx operator)
    tx = None

    assert operator.evaluate(tx, "test_some_pattern") is True
    assert operator.evaluate(tx, "other_pattern") is False
    assert operator.evaluate(tx, "TEST_some_pattern") is False  # Case sensitive


def test_rx_operator_case_insensitive():
    """Test case-insensitive regex operator."""
    options = OperatorOptions(r"(?i)test")
    operator = get_operator("rx", options)

    tx = None

    assert operator.evaluate(tx, "test") is True
    assert operator.evaluate(tx, "TEST") is True
    assert operator.evaluate(tx, "Test") is True
    assert operator.evaluate(tx, "other") is False


def test_eq_operator():
    """Test equality operator."""
    options = OperatorOptions("exact_match")
    operator = get_operator("eq", options)

    tx = None

    assert operator.evaluate(tx, "exact_match") is True
    assert operator.evaluate(tx, "other_value") is False
    assert operator.evaluate(tx, "EXACT_MATCH") is False  # Case sensitive


def test_contains_operator():
    """Test contains operator."""
    options = OperatorOptions("needle")
    operator = get_operator("contains", options)

    tx = None

    assert operator.evaluate(tx, "find_needle_here") is True
    assert operator.evaluate(tx, "needle_at_start") is True
    assert operator.evaluate(tx, "at_end_needle") is True
    assert operator.evaluate(tx, "no_match_here") is False


def test_beginswith_operator():
    """Test beginswith operator."""
    options = OperatorOptions("start")
    operator = get_operator("beginswith", options)

    tx = None

    assert operator.evaluate(tx, "start_of_string") is True
    assert operator.evaluate(tx, "start") is True
    assert operator.evaluate(tx, "not_start") is False
    assert operator.evaluate(tx, "end_start") is False


def test_endswith_operator():
    """Test endswith operator."""
    options = OperatorOptions("end")
    operator = get_operator("endswith", options)

    tx = None

    assert operator.evaluate(tx, "string_end") is True
    assert operator.evaluate(tx, "end") is True
    assert operator.evaluate(tx, "end_not") is False
    assert operator.evaluate(tx, "start_end_middle") is False


def test_gt_operator():
    """Test greater than operator."""
    options = OperatorOptions("5")
    operator = get_operator("gt", options)

    tx = None

    assert operator.evaluate(tx, "10") is True
    assert operator.evaluate(tx, "6") is True
    assert operator.evaluate(tx, "5") is False
    assert operator.evaluate(tx, "4") is False
    assert operator.evaluate(tx, "not_a_number") is False


def test_lt_operator():
    """Test less than operator."""
    options = OperatorOptions("10")
    operator = get_operator("lt", options)

    tx = None

    assert operator.evaluate(tx, "5") is True
    assert operator.evaluate(tx, "9") is True
    assert operator.evaluate(tx, "10") is False
    assert operator.evaluate(tx, "15") is False
    assert operator.evaluate(tx, "not_a_number") is False


def test_ge_operator():
    """Test greater than or equal operator."""
    options = OperatorOptions("5")
    operator = get_operator("ge", options)

    tx = None

    assert operator.evaluate(tx, "10") is True
    assert operator.evaluate(tx, "5") is True
    assert operator.evaluate(tx, "4") is False


def test_le_operator():
    """Test less than or equal operator."""
    options = OperatorOptions("10")
    operator = get_operator("le", options)

    tx = None

    assert operator.evaluate(tx, "5") is True
    assert operator.evaluate(tx, "10") is True
    assert operator.evaluate(tx, "15") is False


def test_within_operator():
    """Test within operator for checking membership."""
    options = OperatorOptions("GET POST PUT")
    operator = get_operator("within", options)

    tx = None

    assert operator.evaluate(tx, "GET") is True
    assert operator.evaluate(tx, "POST") is True
    assert operator.evaluate(tx, "PUT") is True
    assert operator.evaluate(tx, "DELETE") is False
    assert operator.evaluate(tx, "PATCH") is False


def test_streq_operator():
    """Test string equality operator."""
    options = OperatorOptions("test_string")
    operator = get_operator("streq", options)

    tx = None

    assert operator.evaluate(tx, "test_string") is True
    assert operator.evaluate(tx, "other_string") is False
    assert operator.evaluate(tx, "TEST_STRING") is False  # Case sensitive


def test_unconditional_operator():
    """Test unconditional operator (always matches)."""
    options = OperatorOptions("")
    operator = get_operator("unconditional", options)

    tx = None

    assert operator.evaluate(tx, "anything") is True
    assert operator.evaluate(tx, "") is True
    assert operator.evaluate(tx, "12345") is True
