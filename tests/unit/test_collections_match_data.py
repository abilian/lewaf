"""Unit tests for collections match data functionality."""

from coraza_poc.primitives.collections import MatchData


def test_match_data_creation():
    """Test basic MatchData creation."""
    match_data = MatchData("ARGS", "test_key", "test_value")

    assert match_data.variable == "ARGS"
    assert match_data.key == "test_key"
    assert match_data.value == "test_value"


def test_match_data_no_key():
    """Test MatchData creation with empty key."""
    match_data = MatchData("REQUEST_URI", "", "test_value")

    assert match_data.variable == "REQUEST_URI"
    assert match_data.key == ""
    assert match_data.value == "test_value"


def test_match_data_empty_value():
    """Test MatchData with empty value."""
    match_data = MatchData("REQUEST_HEADERS", "empty_key", "")

    assert match_data.variable == "REQUEST_HEADERS"
    assert match_data.key == "empty_key"
    assert match_data.value == ""


def test_match_data_numeric_value():
    """Test MatchData with numeric value as string."""
    match_data = MatchData("TX", "counter", "123")

    assert match_data.variable == "TX"
    assert match_data.key == "counter"
    assert match_data.value == "123"


def test_match_data_none_value():
    """Test MatchData with empty string value."""
    match_data = MatchData("ARGS", "param", "")

    assert match_data.variable == "ARGS"
    assert match_data.key == "param"
    assert match_data.value == ""


def test_match_data_special_characters():
    """Test MatchData with special characters."""
    special_value = "test<>&\"'value"
    match_data = MatchData("ARGS", "special_key", special_value)

    assert match_data.variable == "ARGS"
    assert match_data.key == "special_key"
    assert match_data.value == special_value
