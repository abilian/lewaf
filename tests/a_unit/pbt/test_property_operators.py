"""Property-based tests for operators using Hypothesis.

These tests verify that operators behave correctly across a wide range
of inputs, focusing on:
1. Safety (no crashes on any input)
2. Correctness (mathematical properties hold)
3. Edge cases (empty strings, special characters, etc.)
"""

from __future__ import annotations

import string

from hypothesis import given, settings, strategies as st

from lewaf.primitives.collections import TransactionVariables
from lewaf.primitives.operators import (
    OperatorOptions,
    get_operator,
)


class StubTransaction:
    """Minimal stub transaction for property testing."""

    def __init__(self):
        self.variables = TransactionVariables()
        self.captured_fields: dict[int, str] = {}
        self._capturing = False

    def capturing(self) -> bool:
        return self._capturing

    def capture_field(self, index: int, value: str) -> None:
        self.captured_fields[index] = value


# -----------------------------------------------------------------------------
# Strategies for generating test data
# -----------------------------------------------------------------------------

# Safe text that won't cause encoding issues
safe_text = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=100)

# Numeric strings for comparison operators
numeric_strings = st.one_of(
    st.integers().map(str),
    st.floats(allow_nan=False, allow_infinity=False).map(lambda x: f"{x:.2f}"),
)

# IP addresses
ipv4_addresses = st.tuples(
    st.integers(0, 255),
    st.integers(0, 255),
    st.integers(0, 255),
    st.integers(0, 255),
).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}")


# -----------------------------------------------------------------------------
# Safety Properties: Operators should never crash
# -----------------------------------------------------------------------------


@given(value=safe_text)
@settings(max_examples=100)
def test_eq_operator_no_crash(value: str):
    """@eq should never crash on any input."""
    tx = StubTransaction()
    op = get_operator("eq", OperatorOptions("test"))
    result = op.evaluate(tx, value)
    assert isinstance(result, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_streq_operator_no_crash(value: str):
    """@streq should never crash on any input."""
    tx = StubTransaction()
    op = get_operator("streq", OperatorOptions("test"))
    result = op.evaluate(tx, value)
    assert isinstance(result, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_contains_operator_no_crash(value: str):
    """@contains should never crash on any input."""
    tx = StubTransaction()
    op = get_operator("contains", OperatorOptions("needle"))
    result = op.evaluate(tx, value)
    assert isinstance(result, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_beginswith_operator_no_crash(value: str):
    """@beginsWith should never crash on any input."""
    tx = StubTransaction()
    op = get_operator("beginswith", OperatorOptions("prefix"))
    result = op.evaluate(tx, value)
    assert isinstance(result, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_endswith_operator_no_crash(value: str):
    """@endsWith should never crash on any input."""
    tx = StubTransaction()
    op = get_operator("endswith", OperatorOptions("suffix"))
    result = op.evaluate(tx, value)
    assert isinstance(result, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_rx_operator_no_crash(value: str):
    """@rx should never crash on any input value."""
    tx = StubTransaction()
    op = get_operator("rx", OperatorOptions(r"\w+"))
    result = op.evaluate(tx, value)
    assert isinstance(result, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_pm_operator_no_crash(value: str):
    """@pm should never crash on any input."""
    tx = StubTransaction()
    op = get_operator("pm", OperatorOptions("test pattern foo"))
    result = op.evaluate(tx, value)
    assert isinstance(result, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_within_operator_no_crash(value: str):
    """@within should never crash on any input."""
    tx = StubTransaction()
    op = get_operator("within", OperatorOptions("allowed1 allowed2 allowed3"))
    result = op.evaluate(tx, value)
    assert isinstance(result, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_gt_operator_no_crash(value: str):
    """@gt should never crash on any input (including non-numeric)."""
    tx = StubTransaction()
    op = get_operator("gt", OperatorOptions("5"))
    result = op.evaluate(tx, value)
    assert isinstance(result, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_lt_operator_no_crash(value: str):
    """@lt should never crash on any input (including non-numeric)."""
    tx = StubTransaction()
    op = get_operator("lt", OperatorOptions("5"))
    result = op.evaluate(tx, value)
    assert isinstance(result, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_detectsqli_operator_no_crash(value: str):
    """@detectSQLi should never crash on any input."""
    tx = StubTransaction()
    op = get_operator("detectsqli", OperatorOptions(""))
    result = op.evaluate(tx, value)
    assert isinstance(result, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_detectxss_operator_no_crash(value: str):
    """@detectXSS should never crash on any input."""
    tx = StubTransaction()
    op = get_operator("detectxss", OperatorOptions(""))
    result = op.evaluate(tx, value)
    assert isinstance(result, bool)


# -----------------------------------------------------------------------------
# Correctness Properties: Mathematical invariants
# -----------------------------------------------------------------------------


@given(s=safe_text)
@settings(max_examples=100)
def test_streq_reflexivity(s: str):
    """@streq(s, s) should always be True (reflexivity)."""
    tx = StubTransaction()
    op = get_operator("streq", OperatorOptions(s))
    assert op.evaluate(tx, s) is True


@given(s=safe_text)
@settings(max_examples=100)
def test_eq_reflexivity(s: str):
    """@eq(s, s) should always be True (reflexivity)."""
    tx = StubTransaction()
    op = get_operator("eq", OperatorOptions(s))
    assert op.evaluate(tx, s) is True


@given(s=safe_text)
@settings(max_examples=100)
def test_contains_self(s: str):
    """A string always contains itself."""
    tx = StubTransaction()
    op = get_operator("contains", OperatorOptions(s))
    assert op.evaluate(tx, s) is True


@given(s=safe_text)
@settings(max_examples=100)
def test_contains_empty_string(s: str):
    """Every string contains the empty string."""
    tx = StubTransaction()
    op = get_operator("contains", OperatorOptions(""))
    assert op.evaluate(tx, s) is True


@given(s=safe_text)
@settings(max_examples=100)
def test_beginswith_empty_string(s: str):
    """Every string begins with the empty string."""
    tx = StubTransaction()
    op = get_operator("beginswith", OperatorOptions(""))
    assert op.evaluate(tx, s) is True


@given(s=safe_text)
@settings(max_examples=100)
def test_endswith_empty_string(s: str):
    """Every string ends with the empty string."""
    tx = StubTransaction()
    op = get_operator("endswith", OperatorOptions(""))
    assert op.evaluate(tx, s) is True


@given(s=safe_text)
@settings(max_examples=100)
def test_beginswith_self(s: str):
    """A string always begins with itself."""
    tx = StubTransaction()
    op = get_operator("beginswith", OperatorOptions(s))
    assert op.evaluate(tx, s) is True


@given(s=safe_text)
@settings(max_examples=100)
def test_endswith_self(s: str):
    """A string always ends with itself."""
    tx = StubTransaction()
    op = get_operator("endswith", OperatorOptions(s))
    assert op.evaluate(tx, s) is True


@given(prefix=safe_text, suffix=safe_text)
@settings(max_examples=100)
def test_beginswith_concatenation(prefix: str, suffix: str):
    """If we concatenate prefix+suffix, result begins with prefix."""
    tx = StubTransaction()
    op = get_operator("beginswith", OperatorOptions(prefix))
    assert op.evaluate(tx, prefix + suffix) is True


@given(prefix=safe_text, suffix=safe_text)
@settings(max_examples=100)
def test_endswith_concatenation(prefix: str, suffix: str):
    """If we concatenate prefix+suffix, result ends with suffix."""
    tx = StubTransaction()
    op = get_operator("endswith", OperatorOptions(suffix))
    assert op.evaluate(tx, prefix + suffix) is True


@given(needle=st.text(min_size=1, max_size=10), haystack=safe_text)
@settings(max_examples=100)
def test_contains_implies_substring(needle: str, haystack: str):
    """If @contains returns True, needle is actually in haystack."""
    tx = StubTransaction()
    op = get_operator("contains", OperatorOptions(needle))
    if op.evaluate(tx, haystack):
        assert needle in haystack


@given(s=st.text(min_size=1, max_size=50, alphabet=string.ascii_letters + string.digits))
@settings(max_examples=100)
def test_within_self(s: str):
    """A non-empty word is within a list containing itself."""
    # Note: @within splits the argument by whitespace to get words,
    # so we use only non-whitespace characters (ASCII letters and digits)
    tx = StubTransaction()
    op = get_operator("within", OperatorOptions(s))
    assert op.evaluate(tx, s) is True


# -----------------------------------------------------------------------------
# Numeric Operator Correctness
# -----------------------------------------------------------------------------


@given(n=st.integers(min_value=-1000000, max_value=1000000))
@settings(max_examples=100)
def test_eq_numeric_reflexivity(n: int):
    """@eq(n, n) should be True for numeric values."""
    tx = StubTransaction()
    op = get_operator("eq", OperatorOptions(str(n)))
    assert op.evaluate(tx, str(n)) is True


@given(n=st.integers(min_value=-1000000, max_value=1000000))
@settings(max_examples=100)
def test_lt_irreflexivity(n: int):
    """@lt(n, n) should always be False."""
    tx = StubTransaction()
    op = get_operator("lt", OperatorOptions(str(n)))
    assert op.evaluate(tx, str(n)) is False


@given(n=st.integers(min_value=-1000000, max_value=1000000))
@settings(max_examples=100)
def test_gt_irreflexivity(n: int):
    """@gt(n, n) should always be False."""
    tx = StubTransaction()
    op = get_operator("gt", OperatorOptions(str(n)))
    assert op.evaluate(tx, str(n)) is False


@given(n=st.integers(min_value=-1000000, max_value=1000000))
@settings(max_examples=100)
def test_le_reflexivity(n: int):
    """@le(n, n) should always be True."""
    tx = StubTransaction()
    op = get_operator("le", OperatorOptions(str(n)))
    assert op.evaluate(tx, str(n)) is True


@given(n=st.integers(min_value=-1000000, max_value=1000000))
@settings(max_examples=100)
def test_ge_reflexivity(n: int):
    """@ge(n, n) should always be True."""
    tx = StubTransaction()
    op = get_operator("ge", OperatorOptions(str(n)))
    assert op.evaluate(tx, str(n)) is True


@given(a=st.integers(-10000, 10000), b=st.integers(-10000, 10000))
@settings(max_examples=100)
def test_lt_correctness(a: int, b: int):
    """@lt should correctly compare numeric values."""
    tx = StubTransaction()
    op = get_operator("lt", OperatorOptions(str(b)))
    assert op.evaluate(tx, str(a)) == (a < b)


@given(a=st.integers(-10000, 10000), b=st.integers(-10000, 10000))
@settings(max_examples=100)
def test_gt_correctness(a: int, b: int):
    """@gt should correctly compare numeric values."""
    tx = StubTransaction()
    op = get_operator("gt", OperatorOptions(str(b)))
    assert op.evaluate(tx, str(a)) == (a > b)


@given(a=st.integers(-10000, 10000), b=st.integers(-10000, 10000))
@settings(max_examples=100)
def test_le_correctness(a: int, b: int):
    """@le should correctly compare numeric values."""
    tx = StubTransaction()
    op = get_operator("le", OperatorOptions(str(b)))
    assert op.evaluate(tx, str(a)) == (a <= b)


@given(a=st.integers(-10000, 10000), b=st.integers(-10000, 10000))
@settings(max_examples=100)
def test_ge_correctness(a: int, b: int):
    """@ge should correctly compare numeric values."""
    tx = StubTransaction()
    op = get_operator("ge", OperatorOptions(str(b)))
    assert op.evaluate(tx, str(a)) == (a >= b)


@given(
    a=st.integers(-1000, 1000),
    delta1=st.integers(1, 100),
    delta2=st.integers(1, 100),
)
@settings(max_examples=100)
def test_lt_transitivity(a: int, delta1: int, delta2: int):
    """If a < b and b < c, then a < c (transitivity)."""
    # Construct b and c such that a < b < c by adding positive deltas
    b = a + delta1
    c = b + delta2
    tx = StubTransaction()
    op_ab = get_operator("lt", OperatorOptions(str(b)))
    op_bc = get_operator("lt", OperatorOptions(str(c)))
    op_ac = get_operator("lt", OperatorOptions(str(c)))

    assert op_ab.evaluate(tx, str(a)) is True
    assert op_bc.evaluate(tx, str(b)) is True
    assert op_ac.evaluate(tx, str(a)) is True


# -----------------------------------------------------------------------------
# IP Address Operator Tests
# -----------------------------------------------------------------------------


@given(ip=ipv4_addresses)
@settings(max_examples=50)
def test_ipmatch_self(ip: str):
    """An IP address should match itself."""
    tx = StubTransaction()
    op = get_operator("ipmatch", OperatorOptions(ip))
    assert op.evaluate(tx, ip) is True


@given(ip=ipv4_addresses)
@settings(max_examples=50)
def test_ipmatch_no_crash(ip: str):
    """@ipMatch should not crash on valid IPs."""
    tx = StubTransaction()
    op = get_operator("ipmatch", OperatorOptions("10.0.0.0/8"))
    result = op.evaluate(tx, ip)
    assert isinstance(result, bool)


@given(value=safe_text)
@settings(max_examples=50)
def test_ipmatch_invalid_input_no_crash(value: str):
    """@ipMatch should not crash on invalid IP inputs."""
    tx = StubTransaction()
    op = get_operator("ipmatch", OperatorOptions("10.0.0.0/8"))
    result = op.evaluate(tx, value)
    assert isinstance(result, bool)


# -----------------------------------------------------------------------------
# Unconditional Operators
# -----------------------------------------------------------------------------


@given(value=safe_text)
@settings(max_examples=50)
def test_unconditional_always_true(value: str):
    """@unconditional should always return True."""
    tx = StubTransaction()
    op = get_operator("unconditional", OperatorOptions(""))
    assert op.evaluate(tx, value) is True


@given(value=safe_text)
@settings(max_examples=50)
def test_nomatch_always_false(value: str):
    """@noMatch should always return False."""
    tx = StubTransaction()
    op = get_operator("nomatch", OperatorOptions(""))
    assert op.evaluate(tx, value) is False


# -----------------------------------------------------------------------------
# Validation Operators
# -----------------------------------------------------------------------------


@given(value=st.binary(max_size=100))
@settings(max_examples=50)
def test_validatebyterange_no_crash(value: bytes):
    """@validateByteRange should not crash on any bytes."""
    tx = StubTransaction()
    op = get_operator("validatebyterange", OperatorOptions("0-255"))
    try:
        result = op.evaluate(tx, value.decode("latin-1"))
        assert isinstance(result, bool)
    except UnicodeDecodeError:
        pass  # Expected for some byte sequences


@given(value=safe_text)
@settings(max_examples=50)
def test_validateurlencoding_no_crash(value: str):
    """@validateUrlEncoding should not crash on any input."""
    tx = StubTransaction()
    op = get_operator("validateurlencoding", OperatorOptions(""))
    result = op.evaluate(tx, value)
    assert isinstance(result, bool)
