import pytest
from coraza_poc.primitives.operators import (
    OperatorOptions,
    get_operator,
    RxOperator,
    EqOperator,
    OPERATORS,
)


class MockTransaction:
    """Mock transaction for testing operators."""

    def __init__(self, capturing=False):
        self._capturing = capturing
        self.captured_fields = {}

    def capturing(self):
        return self._capturing

    def capture_field(self, index, value):
        self.captured_fields[index] = value


def test_rx_operator():
    """Tests the RxOperator primitive."""
    op = RxOperator(r"^\d+$")
    tx = MockTransaction()

    assert op.evaluate(tx, "12345") is True
    assert op.evaluate(tx, "abc") is False
    assert op.evaluate(tx, "123a") is False


def test_rx_operator_with_capture():
    """Tests RxOperator with capture groups."""
    op = RxOperator(r"(\w+)=(\d+)")
    tx = MockTransaction(capturing=True)

    assert op.evaluate(tx, "user=123") is True
    assert tx.captured_fields[1] == "user"
    assert tx.captured_fields[2] == "123"

    # Test non-match
    tx_no_match = MockTransaction(capturing=True)
    assert op.evaluate(tx_no_match, "invalid") is False
    assert len(tx_no_match.captured_fields) == 0


def test_eq_operator():
    """Tests the EqOperator primitive."""
    options = OperatorOptions("test123")
    op = get_operator("eq", options)
    tx = MockTransaction()

    assert op.evaluate(tx, "test123") is True
    assert op.evaluate(tx, "test124") is False
    assert op.evaluate(tx, "TEST123") is False  # Case sensitive


def test_contains_operator():
    """Tests the ContainsOperator primitive."""
    options = OperatorOptions("admin")
    op = get_operator("contains", options)
    tx = MockTransaction()

    assert op.evaluate(tx, "administrator") is True
    assert op.evaluate(tx, "user_admin_panel") is True
    assert op.evaluate(tx, "user") is False


def test_beginswith_operator():
    """Tests the BeginsWithOperator primitive."""
    options = OperatorOptions("http://")
    op = get_operator("beginswith", options)
    tx = MockTransaction()

    assert op.evaluate(tx, "http://example.com") is True
    assert op.evaluate(tx, "https://example.com") is False
    assert op.evaluate(tx, "ftp://example.com") is False


def test_endswith_operator():
    """Tests the EndsWithOperator primitive."""
    options = OperatorOptions(".php")
    op = get_operator("endswith", options)
    tx = MockTransaction()

    assert op.evaluate(tx, "index.php") is True
    assert op.evaluate(tx, "script.py") is False
    assert op.evaluate(tx, ".php.bak") is False


def test_operator_factory_pattern():
    """Tests the operator factory pattern."""
    # Test registered operators
    assert "rx" in OPERATORS
    assert "eq" in OPERATORS
    assert "contains" in OPERATORS
    assert "beginswith" in OPERATORS
    assert "endswith" in OPERATORS

    # Test factory creation
    options = OperatorOptions("test")
    rx_op = get_operator("rx", options)
    assert isinstance(rx_op, RxOperator)

    eq_op = get_operator("eq", options)
    assert isinstance(eq_op, EqOperator)


def test_operator_options():
    """Tests OperatorOptions functionality."""
    options = OperatorOptions(
        "pattern", path=["file1.txt"], datasets={"test": ["val1", "val2"]}
    )

    assert options.arguments == "pattern"
    assert options.path == ["file1.txt"]
    assert options.datasets["test"] == ["val1", "val2"]

    # Test defaults
    simple_options = OperatorOptions("simple")
    assert simple_options.path == []
    assert simple_options.datasets == {}


def test_unknown_operator():
    """Tests error handling for unknown operators."""
    options = OperatorOptions("test")

    with pytest.raises(ValueError, match="Unknown operator: nonexistent"):
        get_operator("nonexistent", options)
