"""Unit tests for Phase 6 operators (validatenid, unconditionalmatch alias)."""

from __future__ import annotations

import pytest

from lewaf.primitives.operators import OPERATORS, OperatorOptions
from tests.utils import MockOperatorTransaction


def test_unconditionalmatch_alias_registered():
    """Test that 'unconditionalmatch' alias is registered."""
    assert "unconditionalmatch" in OPERATORS
    assert "unconditional" in OPERATORS
    # Both should point to the same factory
    assert OPERATORS["unconditionalmatch"] == OPERATORS["unconditional"]


def test_unconditionalmatch_behavior():
    """Test that unconditionalmatch always returns True."""
    factory = OPERATORS["unconditionalmatch"]
    options = OperatorOptions("")
    operator = factory.create(options)

    tx = MockOperatorTransaction()

    assert operator.evaluate(tx, "") is True
    assert operator.evaluate(tx, "any value") is True
    assert operator.evaluate(tx, "123") is True


def test_validatenid_registered():
    """Test that 'validatenid' operator is registered."""
    assert "validatenid" in OPERATORS


def test_validatenid_chilean_valid():
    """Test Chilean RUT validation with valid RUTs."""
    factory = OPERATORS["validatenid"]
    options = OperatorOptions(r"cl \d{1,2}\.?\d{3}\.?\d{3}-?[\dkK]")
    operator = factory.create(options)

    tx = MockOperatorTransaction()

    # Valid Chilean RUTs (with correct checksum)
    assert operator.evaluate(tx, "12.345.678-5") is True
    assert operator.evaluate(tx, "12345678-5") is True
    assert operator.evaluate(tx, "123456785") is True

    # RUT with correct verification digit (11.111.111-1)
    assert operator.evaluate(tx, "11.111.111-1") is True
    assert operator.evaluate(tx, "111111111") is True


def test_validatenid_chilean_invalid():
    """Test Chilean RUT validation with invalid RUTs."""
    factory = OPERATORS["validatenid"]
    options = OperatorOptions(r"cl \d{1,2}\.?\d{3}\.?\d{3}-?[\dkK]")
    operator = factory.create(options)

    tx = MockOperatorTransaction()

    # Invalid RUTs (wrong checksum)
    assert operator.evaluate(tx, "12.345.678-9") is False
    assert operator.evaluate(tx, "12345678-9") is False
    assert operator.evaluate(tx, "11.111.111-k") is False  # Should be 1, not k


def test_validatenid_chilean_too_short():
    """Test Chilean RUT validation rejects too-short values."""
    factory = OPERATORS["validatenid"]
    options = OperatorOptions(r"cl \d{1,7}")
    operator = factory.create(options)

    tx = MockOperatorTransaction()

    # Too short (< 8 characters)
    assert operator.evaluate(tx, "1234567") is False
    assert operator.evaluate(tx, "123-4") is False


def test_validatenid_us_valid():
    """Test US SSN validation with valid SSNs."""
    factory = OPERATORS["validatenid"]
    options = OperatorOptions(r"us \d{3}-?\d{2}-?\d{4}")
    operator = factory.create(options)

    tx = MockOperatorTransaction()

    # Valid SSNs (non-sequential, non-repeating, valid ranges)
    assert operator.evaluate(tx, "123-45-6780") is True
    assert operator.evaluate(tx, "001-01-0001") is True
    assert operator.evaluate(tx, "665-12-3456") is True
    assert operator.evaluate(tx, "667-01-0001") is True


def test_validatenid_us_invalid_area():
    """Test US SSN validation rejects invalid area codes."""
    factory = OPERATORS["validatenid"]
    options = OperatorOptions(r"us \d{3}-?\d{2}-?\d{4}")
    operator = factory.create(options)

    tx = MockOperatorTransaction()

    # Invalid area codes
    assert operator.evaluate(tx, "666-45-6789") is False  # 666 forbidden
    assert operator.evaluate(tx, "000-45-6789") is False  # Area cannot be 0
    assert operator.evaluate(tx, "740-01-0001") is False  # Area >= 740
    assert operator.evaluate(tx, "999-01-0001") is False  # Area >= 740


def test_validatenid_us_invalid_group_serial():
    """Test US SSN validation rejects invalid group/serial."""
    factory = OPERATORS["validatenid"]
    options = OperatorOptions(r"us \d{3}-?\d{2}-?\d{4}")
    operator = factory.create(options)

    tx = MockOperatorTransaction()

    # Invalid group (00)
    assert operator.evaluate(tx, "123-00-6789") is False

    # Invalid serial (0000)
    assert operator.evaluate(tx, "123-45-0000") is False


def test_validatenid_us_invalid_patterns():
    """Test US SSN validation rejects repeating and sequential digits."""
    factory = OPERATORS["validatenid"]
    options = OperatorOptions(r"us \d{3}-?\d{2}-?\d{4}")
    operator = factory.create(options)

    tx = MockOperatorTransaction()

    # All same digits
    assert operator.evaluate(tx, "111-11-1111") is False
    assert operator.evaluate(tx, "222-22-2222") is False

    # Sequential digits
    assert operator.evaluate(tx, "123-45-6789") is False


def test_validatenid_us_too_short():
    """Test US SSN validation rejects too-short values."""
    factory = OPERATORS["validatenid"]
    options = OperatorOptions(r"us \d{1,8}")
    operator = factory.create(options)

    tx = MockOperatorTransaction()

    # Too short (< 9 digits)
    assert operator.evaluate(tx, "12345678") is False
    assert operator.evaluate(tx, "123-45-678") is False


def test_validatenid_capture():
    """Test that validatenid captures valid NIDs."""
    factory = OPERATORS["validatenid"]
    options = OperatorOptions(r"cl \d{1,2}\.?\d{3}\.?\d{3}-?[\dkK]")
    operator = factory.create(options)

    tx = MockOperatorTransaction()

    # Should capture valid RUTs (both have correct checksums)
    result = operator.evaluate(tx, "Valid RUT: 12.345.678-5 and 11.111.111-1")
    assert result is True
    assert 0 in tx.captured_fields
    assert tx.captured_fields[0] == "12.345.678-5"
    assert 1 in tx.captured_fields
    assert tx.captured_fields[1] == "11.111.111-1"


def test_validatenid_multiple_matches():
    """Test validatenid with multiple NIDs in input."""
    factory = OPERATORS["validatenid"]
    options = OperatorOptions(r"cl \d{1,2}\.?\d{3}\.?\d{3}-?[\dkK]")
    operator = factory.create(options)

    tx = MockOperatorTransaction()

    # Multiple RUTs, some valid, some invalid
    text = "RUT1: 12.345.678-5 (valid), RUT2: 12.345.678-9 (invalid), RUT3: 11.111.111-k (valid)"
    result = operator.evaluate(tx, text)

    # Should return True because at least one valid NID found
    assert result is True


def test_validatenid_max_matches():
    """Test that validatenid limits matches to 10."""
    factory = OPERATORS["validatenid"]
    options = OperatorOptions(r"cl \d{1,2}\.?\d{3}\.?\d{3}-?[\dkK]")
    operator = factory.create(options)

    tx = MockOperatorTransaction()

    # Create text with 15 valid RUTs
    ruts = ["12.345.678-5"] * 15
    text = " ".join(ruts)

    result = operator.evaluate(tx, text)
    assert result is True

    # Should only capture first 10
    assert len(tx.captured_fields) == 10


def test_validatenid_unsupported_country():
    """Test that unsupported country code raises ValueError."""
    factory = OPERATORS["validatenid"]

    with pytest.raises(ValueError):
        options = OperatorOptions(r"xx \d+")
        _operator = factory.create(options)


def test_validatenid_invalid_format():
    """Test that invalid argument format raises ValueError."""
    factory = OPERATORS["validatenid"]

    with pytest.raises(ValueError):
        options = OperatorOptions("cl")  # Missing regex
        _operator = factory.create(options)
