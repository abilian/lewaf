import pytest

from coraza_poc.primitives.collections import MapCollection


def test_map_collection():
    """Tests the functionality of the MapCollection primitive."""
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
