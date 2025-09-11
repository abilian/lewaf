from __future__ import annotations

from coraza_poc.primitives.transformations import (
    TRANSFORMATIONS,
    compress_whitespace,
    length,
    lowercase,
    remove_whitespace,
    trim,
    uppercase,
)


def test_lowercase_transformation():
    """Tests the lowercase transformation function."""
    result, changed = lowercase("HelloWorld")
    assert result == "helloworld"
    assert changed is True

    result, changed = lowercase("helloworld")
    assert result == "helloworld"
    assert changed is False

    result, changed = lowercase("")
    assert result == ""
    assert changed is False


def test_uppercase_transformation():
    """Tests the uppercase transformation function."""
    result, changed = uppercase("helloworld")
    assert result == "HELLOWORLD"
    assert changed is True

    result, changed = uppercase("HELLOWORLD")
    assert result == "HELLOWORLD"
    assert changed is False


def test_length_transformation():
    """Tests the length transformation function."""
    result, changed = length("hello")
    assert result == "5"
    assert changed is True

    result, changed = length("")
    assert result == "0"
    assert changed is True


def test_trim_transformation():
    """Tests the trim transformation function."""
    result, changed = trim("  hello  ")
    assert result == "hello"
    assert changed is True

    result, changed = trim("hello")
    assert result == "hello"
    assert changed is False


def test_compress_whitespace_transformation():
    """Tests the compress whitespace transformation function."""
    result, changed = compress_whitespace("hello    world  \t\n test")
    assert result == "hello world test"
    assert changed is True

    result, changed = compress_whitespace("hello world")
    assert result == "hello world"
    assert changed is False


def test_remove_whitespace_transformation():
    """Tests the remove whitespace transformation function."""
    result, changed = remove_whitespace("hello world\t\n")
    assert result == "helloworld"
    assert changed is True

    result, changed = remove_whitespace("helloworld")
    assert result == "helloworld"
    assert changed is False


def test_transformation_registry():
    """Tests that transformations are properly registered."""
    assert "lowercase" in TRANSFORMATIONS
    assert "uppercase" in TRANSFORMATIONS
    assert "length" in TRANSFORMATIONS
    assert "trim" in TRANSFORMATIONS
    assert "compresswhitespace" in TRANSFORMATIONS
    assert "removewhitespace" in TRANSFORMATIONS

    # Test registry lookup
    func = TRANSFORMATIONS["lowercase"]
    result, changed = func("TEST")
    assert result == "test"
    assert changed is True
