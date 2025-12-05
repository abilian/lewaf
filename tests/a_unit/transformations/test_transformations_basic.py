"""Unit tests for basic transformations (lowercase, uppercase, trim, etc.)."""

from __future__ import annotations

from lewaf.primitives.transformations import (
    compress_whitespace,
    length,
    lowercase,
    remove_whitespace,
    trim,
    uppercase,
)


def test_lowercase_transformation():
    """Test lowercase transformation."""
    result, changed = lowercase("Hello World")
    assert result == "hello world"
    assert changed is True

    result, changed = lowercase("already lowercase")
    assert result == "already lowercase"
    assert changed is False

    result, changed = lowercase("")
    assert result == ""
    assert changed is False


def test_uppercase_transformation():
    """Test uppercase transformation."""
    result, changed = uppercase("hello world")
    assert result == "HELLO WORLD"
    assert changed is True

    result, changed = uppercase("ALREADY UPPERCASE")
    assert result == "ALREADY UPPERCASE"
    assert changed is False

    result, changed = uppercase("")
    assert result == ""
    assert changed is False


def test_length_transformation():
    """Test length transformation."""
    result, changed = length("hello")
    assert result == "5"
    assert changed is True

    result, changed = length("")
    assert result == "0"
    assert changed is True

    result, changed = length("a")
    assert result == "1"
    assert changed is True


def test_trim_transformation():
    """Test trim transformation."""
    result, changed = trim("  hello world  ")
    assert result == "hello world"
    assert changed is True

    result, changed = trim("\t\nhello\r\n\t")
    assert result == "hello"
    assert changed is True

    result, changed = trim("no spaces")
    assert result == "no spaces"
    assert changed is False

    result, changed = trim("")
    assert result == ""
    assert changed is False


def test_compress_whitespace_transformation():
    """Test compress whitespace transformation."""
    result, changed = compress_whitespace("hello    world")
    assert result == "hello world"
    assert changed is True

    result, changed = compress_whitespace("hello\t\nworld")
    assert result == "hello world"
    assert changed is True

    result, changed = compress_whitespace("hello world")
    assert result == "hello world"
    assert changed is False

    result, changed = compress_whitespace("")
    assert result == ""
    assert changed is False


def test_remove_whitespace_transformation():
    """Test remove whitespace transformation."""
    result, changed = remove_whitespace("hello world")
    assert result == "helloworld"
    assert changed is True

    result, changed = remove_whitespace("a\tb\nc\rd")
    assert result == "abcd"
    assert changed is True

    result, changed = remove_whitespace("nowhitespace")
    assert result == "nowhitespace"
    assert changed is False

    result, changed = remove_whitespace("")
    assert result == ""
    assert changed is False


def test_transformations_with_special_characters():
    """Test transformations with special characters."""
    special_text = "Hello<>&\"'World"

    result, changed = lowercase(special_text)
    assert result == "hello<>&\"'world"
    assert changed is True

    result, changed = uppercase(special_text)
    assert result == "HELLO<>&\"'WORLD"
    assert changed is True

    result, changed = length(special_text)
    assert result == str(len(special_text))
    assert changed is True


def test_transformations_with_unicode():
    """Test transformations with Unicode characters."""
    unicode_text = "Café résumé"

    result, changed = lowercase(unicode_text)
    assert result == "café résumé"
    assert changed is True

    result, changed = uppercase(unicode_text)
    assert result == "CAFÉ RÉSUMÉ"
    assert changed is True

    result, changed = length(unicode_text)
    assert result == str(len(unicode_text))
    assert changed is True


def test_transformations_edge_cases():
    """Test transformations with edge cases."""
    # Test with only whitespace
    result, changed = trim("   ")
    assert result == ""
    assert changed is True

    result, changed = compress_whitespace("   ")
    assert result == " "
    assert changed is True

    result, changed = remove_whitespace("   ")
    assert result == ""
    assert changed is True

    # Test with mixed whitespace types
    mixed_ws = "a\t\r\n b"
    result, changed = compress_whitespace(mixed_ws)
    assert result == "a b"
    assert changed is True
