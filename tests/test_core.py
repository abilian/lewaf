import pytest

from coraza_poc.core import compile_regex


def test_compile_regex_caching():
    """Tests that the regex compilation is properly cached."""
    compile_regex.cache_clear()

    compile_regex("a")
    info = compile_regex.cache_info()
    assert info.misses == 1
    assert info.hits == 0

    compile_regex("a")
    info = compile_regex.cache_info()
    assert info.misses == 1
    assert info.hits == 1

    compile_regex("b")
    info = compile_regex.cache_info()
    assert info.misses == 2
    assert info.hits == 1
