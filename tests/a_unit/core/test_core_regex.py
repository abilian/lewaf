"""Unit tests for core regex compilation functionality."""

from __future__ import annotations

from lewaf.core import compile_regex


def test_compile_regex_basic_pattern():
    """Test basic regex pattern compilation."""
    pattern = r"test.*pattern"
    compiled = compile_regex(pattern)

    assert compiled.pattern == pattern
    assert compiled.match("test_some_pattern") is not None
    assert compiled.match("other_pattern") is None


def test_compile_regex_caching():
    """Test that regex compilation uses caching."""
    pattern = r"cached.*pattern"

    # First compilation
    compiled1 = compile_regex(pattern)

    # Second compilation should return the same object (cached)
    compiled2 = compile_regex(pattern)

    assert compiled1 is compiled2


def test_compile_regex_case_insensitive():
    """Test case-insensitive regex compilation."""
    pattern = r"(?i)test"
    compiled = compile_regex(pattern)

    assert compiled.match("TEST") is not None
    assert compiled.match("Test") is not None
    assert compiled.match("test") is not None


def test_compile_regex_complex_pattern():
    """Test compilation of complex regex patterns."""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    compiled = compile_regex(pattern)

    assert compiled.match("test@example.com") is not None
    assert compiled.match("invalid-email") is None


def test_compile_regex_empty_pattern():
    """Test compilation of empty pattern."""
    pattern = ""
    compiled = compile_regex(pattern)

    assert compiled.pattern == pattern
    assert compiled.match("") is not None
    assert compiled.match("any") is not None  # Empty pattern matches everything


def test_compile_regex_special_characters():
    """Test compilation with special regex characters."""
    pattern = r"\d+\.\d+\.\d+\.\d+"  # IP address pattern
    compiled = compile_regex(pattern)

    assert compiled.match("192.168.1.1") is not None
    assert compiled.match("10.0.0.1") is not None
    assert compiled.match("not.an.ip") is None
