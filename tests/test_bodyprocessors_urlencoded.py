"""Tests for URLEncoded body processor."""

import pytest

from lewaf.bodyprocessors import BodyProcessorError, get_body_processor
from lewaf.bodyprocessors.urlencoded import URLEncodedProcessor


def test_urlencoded_processor_basic():
    """Test basic URL-encoded form parsing."""
    processor = URLEncodedProcessor()
    body = b"username=admin&password=secret&submit=Login"

    processor.read(body, "application/x-www-form-urlencoded")

    collections = processor.get_collections()
    assert "args_post" in collections
    assert "request_body" in collections

    args_post = collections["args_post"]
    assert args_post["username"] == "admin"
    assert args_post["password"] == "secret"
    assert args_post["submit"] == "Login"

    request_body = collections["request_body"]
    assert request_body == "username=admin&password=secret&submit=Login"


def test_urlencoded_processor_special_chars():
    """Test URL-encoded special characters."""
    processor = URLEncodedProcessor()
    body = b"name=John+Doe&email=john%40example.com&message=Hello%20World%21"

    processor.read(body, "application/x-www-form-urlencoded")

    args_post = processor.get_collections()["args_post"]
    assert args_post["name"] == "John Doe"
    assert args_post["email"] == "john@example.com"
    assert args_post["message"] == "Hello World!"


def test_urlencoded_processor_empty_values():
    """Test URL-encoded empty values."""
    processor = URLEncodedProcessor()
    body = b"key1=&key2=value&key3="

    processor.read(body, "application/x-www-form-urlencoded")

    args_post = processor.get_collections()["args_post"]
    assert args_post["key1"] == ""
    assert args_post["key2"] == "value"
    assert args_post["key3"] == ""


def test_urlencoded_processor_multiple_values():
    """Test URL-encoded multiple values (takes first)."""
    processor = URLEncodedProcessor()
    body = b"color=red&color=blue&color=green"

    processor.read(body, "application/x-www-form-urlencoded")

    args_post = processor.get_collections()["args_post"]
    # Should take first value (ModSecurity behavior)
    assert args_post["color"] == "red"


def test_urlencoded_processor_no_params():
    """Test URL-encoded with no parameters."""
    processor = URLEncodedProcessor()
    body = b""

    processor.read(body, "application/x-www-form-urlencoded")

    args_post = processor.get_collections()["args_post"]
    assert len(args_post) == 0


def test_urlencoded_processor_invalid_utf8():
    """Test URL-encoded with invalid UTF-8."""
    processor = URLEncodedProcessor()
    # Invalid UTF-8 sequence
    body = b"name=\xff\xfe"

    with pytest.raises(BodyProcessorError, match="Invalid UTF-8"):
        processor.read(body, "application/x-www-form-urlencoded")


def test_urlencoded_processor_find():
    """Test find() method (not supported for URLEncoded)."""
    processor = URLEncodedProcessor()
    body = b"username=admin"

    processor.read(body, "application/x-www-form-urlencoded")

    # URLEncoded doesn't support find()
    result = processor.find("username")
    assert result == []


def test_urlencoded_registry():
    """Test URLEncoded processor via registry."""
    processor = get_body_processor("URLENCODED")
    assert isinstance(processor, URLEncodedProcessor)

    body = b"test=value"
    processor.read(body, "application/x-www-form-urlencoded")

    args_post = processor.get_collections()["args_post"]
    assert args_post["test"] == "value"


def test_urlencoded_case_insensitive():
    """Test registry is case-insensitive."""
    processor1 = get_body_processor("urlencoded")
    processor2 = get_body_processor("URLENCODED")
    processor3 = get_body_processor("UrlEncoded")

    assert isinstance(processor1, URLEncodedProcessor)
    assert isinstance(processor2, URLEncodedProcessor)
    assert isinstance(processor3, URLEncodedProcessor)
