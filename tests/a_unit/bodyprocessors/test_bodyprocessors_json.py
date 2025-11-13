"""Tests for JSON body processor."""

from __future__ import annotations

import json

import pytest

from lewaf.bodyprocessors import get_body_processor
from lewaf.bodyprocessors.json import JSONProcessor
from lewaf.exceptions import InvalidJSONError


def test_json_processor_basic():
    """Test basic JSON object parsing."""
    processor = JSONProcessor()
    data = {"username": "admin", "password": "secret", "remember": True}
    body = json.dumps(data).encode("utf-8")

    processor.read(body, "application/json")

    collections = processor.get_collections()
    assert "args_post" in collections
    assert "request_body" in collections

    args_post = collections["args_post"]
    assert args_post["username"] == "admin"
    assert args_post["password"] == "secret"
    assert args_post["remember"] == "True"


def test_json_processor_nested():
    """Test nested JSON object parsing."""
    processor = JSONProcessor()
    data = {"user": {"name": "admin", "id": 123}, "action": "login"}
    body = json.dumps(data).encode("utf-8")

    processor.read(body, "application/json")

    args_post = processor.get_collections()["args_post"]
    assert args_post["user.name"] == "admin"
    assert args_post["user.id"] == "123"
    assert args_post["action"] == "login"


def test_json_processor_arrays():
    """Test JSON arrays."""
    processor = JSONProcessor()
    data = {"tags": ["security", "waf", "owasp"], "count": 3}
    body = json.dumps(data).encode("utf-8")

    processor.read(body, "application/json")

    args_post = processor.get_collections()["args_post"]
    assert args_post["tags[0]"] == "security"
    assert args_post["tags[1]"] == "waf"
    assert args_post["tags[2]"] == "owasp"
    assert args_post["count"] == "3"


def test_json_processor_nested_arrays():
    """Test nested arrays in JSON."""
    processor = JSONProcessor()
    data = {"users": [{"name": "alice", "age": 30}, {"name": "bob", "age": 25}]}
    body = json.dumps(data).encode("utf-8")

    processor.read(body, "application/json")

    args_post = processor.get_collections()["args_post"]
    assert args_post["users[0].name"] == "alice"
    assert args_post["users[0].age"] == "30"
    assert args_post["users[1].name"] == "bob"
    assert args_post["users[1].age"] == "25"


def test_json_processor_null_values():
    """Test JSON null values."""
    processor = JSONProcessor()
    data = {"key1": None, "key2": "value"}
    body = json.dumps(data).encode("utf-8")

    processor.read(body, "application/json")

    args_post = processor.get_collections()["args_post"]
    assert args_post["key1"] == ""
    assert args_post["key2"] == "value"


def test_json_processor_primitive_types():
    """Test JSON primitive types."""
    processor = JSONProcessor()
    data = {
        "string": "text",
        "number": 42,
        "float": 3.14,
        "bool_true": True,
        "bool_false": False,
    }
    body = json.dumps(data).encode("utf-8")

    processor.read(body, "application/json")

    args_post = processor.get_collections()["args_post"]
    assert args_post["string"] == "text"
    assert args_post["number"] == "42"
    assert args_post["float"] == "3.14"
    assert args_post["bool_true"] == "True"
    assert args_post["bool_false"] == "False"


def test_json_processor_root_array():
    """Test JSON with array at root."""
    processor = JSONProcessor()
    data = [{"id": 1, "name": "item1"}, {"id": 2, "name": "item2"}]
    body = json.dumps(data).encode("utf-8")

    processor.read(body, "application/json")

    args_post = processor.get_collections()["args_post"]
    assert args_post["[0].id"] == "1"
    assert args_post["[0].name"] == "item1"
    assert args_post["[1].id"] == "2"
    assert args_post["[1].name"] == "item2"


def test_json_processor_root_primitive():
    """Test JSON with primitive at root."""
    processor = JSONProcessor()
    body = b'"simple string"'

    processor.read(body, "application/json")

    args_post = processor.get_collections()["args_post"]
    assert args_post["value"] == "simple string"


def test_json_processor_empty_object():
    """Test empty JSON object."""
    processor = JSONProcessor()
    body = b"{}"

    processor.read(body, "application/json")

    args_post = processor.get_collections()["args_post"]
    assert len(args_post) == 0


def test_json_processor_invalid_json():
    """Test invalid JSON."""
    processor = JSONProcessor()
    body = b'{"invalid": json}'

    with pytest.raises(InvalidJSONError, match="Invalid JSON"):
        processor.read(body, "application/json")


def test_json_processor_invalid_utf8():
    """Test invalid UTF-8 in JSON body."""
    processor = JSONProcessor()
    body = b"\xff\xfe{}"

    with pytest.raises(InvalidJSONError, match="Invalid UTF-8"):
        processor.read(body, "application/json")


def test_json_processor_find_simple():
    """Test find() with simple path."""
    processor = JSONProcessor()
    data = {"user": {"name": "admin", "id": 123}}
    body = json.dumps(data).encode("utf-8")

    processor.read(body, "application/json")

    # Test with $.notation
    assert processor.find("$.user.name") == ["admin"]
    assert processor.find("$.user.id") == ["123"]

    # Test without $ prefix
    assert processor.find("user.name") == ["admin"]
    assert processor.find("user.id") == ["123"]


def test_json_processor_find_array():
    """Test find() with array indexing."""
    processor = JSONProcessor()
    data = {"users": ["alice", "bob", "charlie"]}
    body = json.dumps(data).encode("utf-8")

    processor.read(body, "application/json")

    assert processor.find("$.users[0]") == ["alice"]
    assert processor.find("$.users[1]") == ["bob"]
    assert processor.find("$.users[2]") == ["charlie"]


def test_json_processor_find_nested_array():
    """Test find() with nested arrays."""
    processor = JSONProcessor()
    data = {"users": [{"name": "alice"}, {"name": "bob"}]}
    body = json.dumps(data).encode("utf-8")

    processor.read(body, "application/json")

    assert processor.find("$.users[0].name") == ["alice"]
    assert processor.find("$.users[1].name") == ["bob"]


def test_json_processor_find_root():
    """Test find() for root."""
    processor = JSONProcessor()
    data = {"key": "value"}
    body = json.dumps(data).encode("utf-8")

    processor.read(body, "application/json")

    result = processor.find("$")
    assert len(result) == 1
    assert json.loads(result[0]) == data


def test_json_processor_find_not_found():
    """Test find() with non-existent path."""
    processor = JSONProcessor()
    data = {"key": "value"}
    body = json.dumps(data).encode("utf-8")

    processor.read(body, "application/json")

    assert processor.find("$.nonexistent") == []
    assert processor.find("$.key.nested") == []


def test_json_processor_find_complex():
    """Test find() returning complex objects."""
    processor = JSONProcessor()
    data = {"user": {"profile": {"name": "admin", "age": 30}}}
    body = json.dumps(data).encode("utf-8")

    processor.read(body, "application/json")

    result = processor.find("$.user.profile")
    assert len(result) == 1
    assert json.loads(result[0]) == {"name": "admin", "age": 30}


def test_json_processor_max_depth():
    """Test JSON depth limit protection."""
    processor = JSONProcessor()

    # Create deeply nested JSON (beyond max_depth)
    # Add a value at an intermediate level so we have something to verify
    data = {
        "level0": {
            "value_at_0": "accessible",
            "level1": {
                "value_at_1": "accessible",
                "level2": {
                    "value_at_2": "accessible",
                    "level3": {
                        "level4": {
                            "level5": {
                                "level6": {
                                    "level7": {
                                        "level8": {
                                            "level9": {
                                                "value_at_9": "accessible",
                                                "level10": {"level11": "too_deep"},
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            },
        }
    }
    body = json.dumps(data).encode("utf-8")

    # Should not crash, but will truncate at max_depth
    processor.read(body, "application/json")

    args_post = processor.get_collections()["args_post"]
    # Should have keys up to max_depth
    assert "level0.value_at_0" in args_post
    assert "level0.level1.value_at_1" in args_post
    assert "level0.level1.level2.value_at_2" in args_post
    # Deep values within limit should be accessible
    assert args_post["level0.value_at_0"] == "accessible"
    # But the deepest value (level 11) should not be present
    # (it's beyond max_depth of 10)


def test_json_processor_registry():
    """Test JSON processor via registry."""
    processor = get_body_processor("JSON")
    assert isinstance(processor, JSONProcessor)

    data = {"test": "value"}
    body = json.dumps(data).encode("utf-8")
    processor.read(body, "application/json")

    args_post = processor.get_collections()["args_post"]
    assert args_post["test"] == "value"


def test_json_processor_special_chars():
    """Test JSON with special characters."""
    processor = JSONProcessor()
    data = {
        "sql": "SELECT * FROM users WHERE id=1; DROP TABLE users;--",
        "xss": "<script>alert('xss')</script>",
        "unicode": "Hello 世界 🌍",
    }
    body = json.dumps(data).encode("utf-8")

    processor.read(body, "application/json")

    args_post = processor.get_collections()["args_post"]
    assert args_post["sql"] == "SELECT * FROM users WHERE id=1; DROP TABLE users;--"
    assert args_post["xss"] == "<script>alert('xss')</script>"
    assert args_post["unicode"] == "Hello 世界 🌍"
