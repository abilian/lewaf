"""Property-based tests for collections using Hypothesis.

These tests verify collection correctness across a wide range of inputs:
1. Basic CRUD operations work correctly
2. Case sensitivity behaves as expected
3. Multiple values per key are handled correctly
4. Edge cases (empty strings, special characters) work
"""

from __future__ import annotations

import pytest
from hypothesis import assume, given, settings, strategies as st

from lewaf.primitives.collections import (
    MapCollection,
    MatchData,
    SingleValueCollection,
)

# -----------------------------------------------------------------------------
# Strategies for generating test data
# -----------------------------------------------------------------------------

# Safe text without surrogate characters
safe_text = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=50)

# Non-empty safe text for keys
non_empty_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=50
)

# Key-value pairs
key_value_pairs = st.tuples(non_empty_text, safe_text)


# -----------------------------------------------------------------------------
# MapCollection Properties
# -----------------------------------------------------------------------------


@given(key=non_empty_text, value=safe_text)
@settings(max_examples=100)
def test_mapcollection_add_then_get(key: str, value: str):
    """After adding a key-value pair, get should return it."""
    collection = MapCollection("TEST")
    collection.add(key, value)
    result = collection.get(key)
    assert value in result


@given(key=non_empty_text, values=st.lists(safe_text, min_size=1, max_size=5))
@settings(max_examples=100)
def test_mapcollection_set_then_get(key: str, values: list[str]):
    """After setting values for a key, get should return exactly those values."""
    collection = MapCollection("TEST")
    collection.set(key, values)
    result = collection.get(key)
    assert result == values


@given(key=non_empty_text, value=safe_text)
@settings(max_examples=100)
def test_mapcollection_add_then_remove(key: str, value: str):
    """After removing a key, get should return empty list."""
    collection = MapCollection("TEST")
    collection.add(key, value)
    collection.remove(key)
    result = collection.get(key)
    assert result == []


@given(key=non_empty_text, values=st.lists(safe_text, min_size=2, max_size=5))
@settings(max_examples=100)
def test_mapcollection_multiple_values(key: str, values: list[str]):
    """Adding multiple values to same key should accumulate them."""
    collection = MapCollection("TEST")
    for v in values:
        collection.add(key, v)
    result = collection.get(key)
    assert result == values


@given(key=non_empty_text)
@settings(max_examples=100)
def test_mapcollection_get_nonexistent_key(key: str):
    """Getting a nonexistent key should return empty list."""
    collection = MapCollection("TEST")
    result = collection.get(key)
    assert result == []


@given(key=st.text(alphabet=st.characters(categories=("Lu", "Ll")), min_size=1, max_size=20), value=safe_text)
@settings(max_examples=100)
def test_mapcollection_case_insensitive_default(key: str, value: str):
    """MapCollection is case-insensitive by default."""
    # Use only letters that have distinct upper/lower forms
    assume(any(c.isupper() or c.islower() for c in key))
    collection = MapCollection("TEST", case_insensitive=True)
    collection.add(key, value)
    # Get with different case - should still find it
    result = collection.get(key.lower())
    assert value in result


@given(key=non_empty_text, value=safe_text)
@settings(max_examples=100)
def test_mapcollection_case_sensitive(key: str, value: str):
    """MapCollection can be case-sensitive."""
    assume(key.lower() != key.upper())  # Ensure key has case-variant characters
    collection = MapCollection("TEST", case_insensitive=False)
    collection.add(key.lower(), value)
    # Different case should not find the value
    if key.lower() != key.upper():
        result = collection.get(key.upper())
        assert value not in result


@given(key=non_empty_text, value=safe_text)
@settings(max_examples=100)
def test_mapcollection_find_all_contains_added(key: str, value: str):
    """find_all should return all added key-value pairs."""
    collection = MapCollection("TEST")
    collection.add(key, value)
    matches = collection.find_all()
    # At least one match should have our value
    assert any(m.value == value for m in matches)


@given(key=non_empty_text, value=safe_text)
@settings(max_examples=100)
def test_mapcollection_find_string(key: str, value: str):
    """find_string should find exact key matches."""
    collection = MapCollection("TEST")
    collection.add(key, value)
    matches = collection.find_string(key)
    assert len(matches) == 1
    assert matches[0].value == value


@given(pairs=st.lists(key_value_pairs, min_size=1, max_size=10))
@settings(max_examples=100)
def test_mapcollection_find_all_count(pairs: list[tuple[str, str]]):
    """find_all should return correct number of entries."""
    collection = MapCollection("TEST")
    for key, value in pairs:
        collection.add(key, value)
    matches = collection.find_all()
    assert len(matches) == len(pairs)


@given(key=non_empty_text, v1=safe_text, v2=safe_text)
@settings(max_examples=100)
def test_mapcollection_set_replaces(key: str, v1: str, v2: str):
    """set should replace existing values, not append."""
    collection = MapCollection("TEST")
    collection.add(key, v1)
    collection.set(key, [v2])
    result = collection.get(key)
    assert result == [v2]
    assert v1 not in result or v1 == v2


# -----------------------------------------------------------------------------
# SingleValueCollection Properties
# -----------------------------------------------------------------------------


@given(value=safe_text)
@settings(max_examples=100)
def test_singlevaluecollection_set_then_get(value: str):
    """After setting a value, get should return it."""
    collection = SingleValueCollection("TEST")
    collection.set(value)
    result = collection.get()
    assert result == value


@given(v1=safe_text, v2=safe_text)
@settings(max_examples=100)
def test_singlevaluecollection_last_write_wins(v1: str, v2: str):
    """Setting twice should keep the last value."""
    collection = SingleValueCollection("TEST")
    collection.set(v1)
    collection.set(v2)
    result = collection.get()
    assert result == v2


@given(value=safe_text)
@settings(max_examples=100)
def test_singlevaluecollection_find_all(value: str):
    """find_all should return the single value as MatchData."""
    collection = SingleValueCollection("TEST")
    collection.set(value)
    matches = collection.find_all()
    assert len(matches) == 1
    assert matches[0].value == value
    assert matches[0].key == ""
    assert matches[0].variable == "TEST"


def test_singlevaluecollection_initial_empty():
    """Initial value should be empty string."""
    collection = SingleValueCollection("TEST")
    assert collection.get() == ""


# -----------------------------------------------------------------------------
# MatchData Properties
# -----------------------------------------------------------------------------


@given(variable=non_empty_text, key=safe_text, value=safe_text)
@settings(max_examples=100)
def test_matchdata_immutable(variable: str, key: str, value: str):
    """MatchData should be immutable (frozen dataclass)."""
    match = MatchData(variable=variable, key=key, value=value)
    assert match.variable == variable
    assert match.key == key
    assert match.value == value

    # Verify immutability - frozen dataclass should raise on assignment
    with pytest.raises(AttributeError):
        match.value = "new_value"  # type: ignore


@given(variable=non_empty_text, key=safe_text, value=safe_text)
@settings(max_examples=100)
def test_matchdata_equality(variable: str, key: str, value: str):
    """MatchData with same values should be equal."""
    match1 = MatchData(variable=variable, key=key, value=value)
    match2 = MatchData(variable=variable, key=key, value=value)
    assert match1 == match2


@given(
    var1=non_empty_text,
    var2=non_empty_text,
    key=safe_text,
    value=safe_text,
)
@settings(max_examples=100)
def test_matchdata_inequality(var1: str, var2: str, key: str, value: str):
    """MatchData with different values should not be equal."""
    assume(var1 != var2)
    match1 = MatchData(variable=var1, key=key, value=value)
    match2 = MatchData(variable=var2, key=key, value=value)
    assert match1 != match2


# -----------------------------------------------------------------------------
# Collection Name Properties
# -----------------------------------------------------------------------------


@given(name=non_empty_text)
@settings(max_examples=100)
def test_mapcollection_name(name: str):
    """MapCollection should preserve its name."""
    collection = MapCollection(name)
    assert collection.name() == name


@given(name=non_empty_text)
@settings(max_examples=100)
def test_singlevaluecollection_name(name: str):
    """SingleValueCollection should preserve its name."""
    collection = SingleValueCollection(name)
    assert collection.name() == name


# -----------------------------------------------------------------------------
# Edge Cases
# -----------------------------------------------------------------------------


def test_mapcollection_empty_key():
    """MapCollection should handle empty string as key."""
    collection = MapCollection("TEST")
    collection.add("", "value")
    result = collection.get("")
    assert "value" in result


def test_mapcollection_empty_value():
    """MapCollection should handle empty string as value."""
    collection = MapCollection("TEST")
    collection.add("key", "")
    result = collection.get("key")
    assert "" in result


def test_singlevaluecollection_empty_value():
    """SingleValueCollection should handle empty string as value."""
    collection = SingleValueCollection("TEST")
    collection.set("")
    assert collection.get() == ""


@given(key=non_empty_text, value=safe_text)
@settings(max_examples=100)
def test_mapcollection_remove_idempotent(key: str, value: str):
    """Removing a key multiple times should be safe."""
    collection = MapCollection("TEST")
    collection.add(key, value)
    collection.remove(key)
    collection.remove(key)  # Second remove should not raise
    assert collection.get(key) == []


@given(key=non_empty_text)
@settings(max_examples=100)
def test_mapcollection_remove_nonexistent(key: str):
    """Removing a nonexistent key should be safe."""
    collection = MapCollection("TEST")
    collection.remove(key)  # Should not raise
    assert collection.get(key) == []


# -----------------------------------------------------------------------------
# Stress Tests
# -----------------------------------------------------------------------------


@given(
    pairs=st.lists(key_value_pairs, min_size=10, max_size=50),
)
@settings(max_examples=20)
def test_mapcollection_many_entries(pairs: list[tuple[str, str]]):
    """MapCollection should handle many entries correctly."""
    collection = MapCollection("TEST")
    for key, value in pairs:
        collection.add(key, value)

    # All values should be retrievable
    matches = collection.find_all()
    assert len(matches) == len(pairs)


@given(values=st.lists(safe_text, min_size=10, max_size=50))
@settings(max_examples=20)
def test_mapcollection_many_values_per_key(values: list[str]):
    """MapCollection should handle many values per key."""
    collection = MapCollection("TEST")
    for value in values:
        collection.add("key", value)

    result = collection.get("key")
    assert result == values
