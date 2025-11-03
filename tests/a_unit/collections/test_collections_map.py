"""Unit tests for MapCollection functionality."""

import re

from lewaf.primitives.collections import MapCollection


def test_map_collection_creation():
    """Test basic MapCollection creation."""
    collection = MapCollection("TEST_MAP")

    assert collection.name() == "TEST_MAP"
    assert len(collection.find_all()) == 0


def test_map_collection_add_single_value():
    """Test adding a single value to MapCollection."""
    collection = MapCollection("TEST_MAP")
    collection.add("key1", "value1")

    all_matches = collection.find_all()
    assert len(all_matches) == 1
    assert all_matches[0].variable == "TEST_MAP"
    assert all_matches[0].key == "key1"
    assert all_matches[0].value == "value1"


def test_map_collection_add_multiple_values():
    """Test adding multiple values to the same key."""
    collection = MapCollection("TEST_MAP")
    collection.add("key1", "value1")
    collection.add("key1", "value2")

    all_matches = collection.find_all()
    assert len(all_matches) == 2

    values = [match.value for match in all_matches]
    assert "value1" in values
    assert "value2" in values

    # All should have same key and variable
    for match in all_matches:
        assert match.key == "key1"
        assert match.variable == "TEST_MAP"


def test_map_collection_case_sensitivity():
    """Test case sensitivity in MapCollection."""
    collection = MapCollection("TEST_MAP")
    collection.add("Key1", "Value1")

    # Default is case insensitive
    matches = collection.find_string("key1")
    assert len(matches) == 1
    assert matches[0].value == "Value1"

    # Test case sensitive collection
    case_sensitive = MapCollection("TEST_MAP", case_insensitive=False)
    case_sensitive.add("Key1", "Value1")

    matches = case_sensitive.find_string("key1")
    assert len(matches) == 0

    matches = case_sensitive.find_string("Key1")
    assert len(matches) == 1


def test_map_collection_remove():
    """Test removing keys from MapCollection."""
    collection = MapCollection("TEST_MAP")
    collection.add("key1", "value1")
    collection.add("key2", "value2")

    collection.remove("key1")

    all_matches = collection.find_all()
    assert len(all_matches) == 1
    assert all_matches[0].key == "key2"


def test_map_collection_set_replaces_value():
    """Test that set replaces all values for a key."""
    collection = MapCollection("TEST_MAP")
    collection.add("key1", "value1")
    collection.add("key1", "value2")

    collection.set("key1", ["new_value"])

    matches = collection.find_string("key1")
    assert len(matches) == 1
    assert matches[0].value == "new_value"


def test_map_collection_find_regex():
    """Test regex pattern matching in MapCollection."""
    collection = MapCollection("TEST_MAP")
    collection.add("user_name", "john")
    collection.add("user_email", "john@example.com")
    collection.add("admin_role", "admin")

    pattern = re.compile(r"user_.*")
    matches = collection.find_regex(pattern)

    assert len(matches) == 2
    keys = [match.key for match in matches]
    assert "user_name" in keys
    assert "user_email" in keys


def test_map_collection_find_string_pattern():
    """Test exact string matching in MapCollection."""
    collection = MapCollection("TEST_MAP")
    collection.add("exact_key", "value1")
    collection.add("other_key", "value2")

    matches = collection.find_string("exact_key")
    assert len(matches) == 1
    assert matches[0].value == "value1"

    matches = collection.find_string("nonexistent")
    assert len(matches) == 0


def test_map_collection_empty_search():
    """Test searching in empty MapCollection."""
    collection = MapCollection("TEST_MAP")

    matches = collection.find_string("any_key")
    assert len(matches) == 0

    pattern = re.compile(r".*")
    matches = collection.find_regex(pattern)
    assert len(matches) == 0


def test_map_collection_special_characters():
    """Test MapCollection with special characters."""
    collection = MapCollection("TEST_MAP")
    special_key = "key<>&\"'"
    special_value = "value<>&\"'"

    collection.add(special_key, special_value)

    all_matches = collection.find_all()
    assert len(all_matches) == 1
    assert all_matches[0].key == special_key.lower()  # Case insensitive by default
    assert all_matches[0].value == special_value
