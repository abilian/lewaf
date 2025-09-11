import re
from coraza_poc.primitives.collections import (
    MatchData,
    MapCollection,
    SingleValueCollection,
    TransactionVariables,
)


def test_match_data():
    """Tests MatchData functionality."""
    match = MatchData("ARGS", "username", "admin")
    assert match.variable == "ARGS"
    assert match.key == "username"
    assert match.value == "admin"
    assert "ARGS" in str(match)
    assert "username" in str(match)
    assert "admin" in str(match)


def test_map_collection_basic():
    """Tests basic functionality of the MapCollection primitive."""
    mc = MapCollection("TEST_VARS")
    mc.add("Key1", "Value1")
    mc.add("key1", "Value2")

    assert mc.get("key1") == ["Value1", "Value2"]
    assert mc.get("KEY1") == ["Value1", "Value2"]
    assert mc.get("nonexistent") == []

    all_matches = mc.find_all()
    assert len(all_matches) == 2

    values = {m.value for m in all_matches}
    assert values == {"Value1", "Value2"}


def test_map_collection_case_sensitivity():
    """Tests case sensitivity behavior."""
    # Case insensitive (default)
    mc_insensitive = MapCollection("TEST", case_insensitive=True)
    mc_insensitive.add("Key1", "Value1")
    mc_insensitive.add("KEY1", "Value2")
    assert mc_insensitive.get("key1") == ["Value1", "Value2"]

    # Case sensitive
    mc_sensitive = MapCollection("TEST", case_insensitive=False)
    mc_sensitive.add("Key1", "Value1")
    mc_sensitive.add("KEY1", "Value2")
    assert mc_sensitive.get("Key1") == ["Value1"]
    assert mc_sensitive.get("KEY1") == ["Value2"]
    assert mc_sensitive.get("key1") == []


def test_map_collection_set_and_remove():
    """Tests set and remove methods."""
    mc = MapCollection("TEST")

    # Test set method
    mc.set("key1", ["val1", "val2", "val3"])
    assert mc.get("key1") == ["val1", "val2", "val3"]

    # Test replace existing
    mc.set("key1", ["newval"])
    assert mc.get("key1") == ["newval"]

    # Test remove
    mc.remove("key1")
    assert mc.get("key1") == []

    # Test remove non-existent key
    mc.remove("nonexistent")  # Should not raise error


def test_map_collection_find_regex():
    """Tests find_regex method."""
    mc = MapCollection("TEST")
    mc.add("user_id", "123")
    mc.add("user_name", "admin")
    mc.add("session_id", "abc456")
    mc.add("other", "value")

    # Find keys starting with "user"
    pattern = re.compile(r"^user")
    matches = mc.find_regex(pattern)
    assert len(matches) == 2

    keys = {m.key for m in matches}
    assert keys == {"user_id", "user_name"}

    # Find keys ending with "_id"
    pattern = re.compile(r"_id$")
    matches = mc.find_regex(pattern)
    assert len(matches) == 2

    keys = {m.key for m in matches}
    assert keys == {"user_id", "session_id"}


def test_map_collection_find_string():
    """Tests find_string method."""
    mc = MapCollection("TEST")
    mc.add("key1", "value1")
    mc.add("key1", "value2")
    mc.add("key2", "value3")

    matches = mc.find_string("key1")
    assert len(matches) == 2
    values = {m.value for m in matches}
    assert values == {"value1", "value2"}

    matches = mc.find_string("key2")
    assert len(matches) == 1
    assert matches[0].value == "value3"

    matches = mc.find_string("nonexistent")
    assert len(matches) == 0


def test_single_value_collection():
    """Tests SingleValueCollection functionality."""
    svc = SingleValueCollection("REQUEST_URI")

    # Test initial state
    assert svc.get() == ""
    assert svc.name() == "REQUEST_URI"

    # Test set and get
    svc.set("/path/to/resource")
    assert svc.get() == "/path/to/resource"

    # Test find_all
    matches = svc.find_all()
    assert len(matches) == 1
    assert matches[0].variable == "REQUEST_URI"
    assert matches[0].key == ""
    assert matches[0].value == "/path/to/resource"


def test_transaction_variables():
    """Tests TransactionVariables container."""
    tv = TransactionVariables()

    # Test that all expected collections exist
    assert isinstance(tv.args, MapCollection)
    assert isinstance(tv.request_headers, MapCollection)
    assert isinstance(tv.tx, MapCollection)
    assert isinstance(tv.request_uri, SingleValueCollection)

    # Test names
    assert tv.args.name() == "ARGS"
    assert tv.request_headers.name() == "REQUEST_HEADERS"
    assert tv.tx.name() == "TX"
    assert tv.request_uri.name() == "REQUEST_URI"

    # Test TX is case sensitive
    tv.tx.add("Key1", "value1")
    tv.tx.add("key1", "value2")
    assert tv.tx.get("Key1") == ["value1"]
    assert tv.tx.get("key1") == ["value2"]

    # Test others are case insensitive
    tv.args.add("Key1", "value1")
    tv.args.add("key1", "value2")
    assert tv.args.get("key1") == ["value1", "value2"]


def test_collection_name_method():
    """Tests the name() method across all collection types."""
    mc = MapCollection("TEST_MAP")
    svc = SingleValueCollection("TEST_SINGLE")

    assert mc.name() == "TEST_MAP"
    assert svc.name() == "TEST_SINGLE"
