"""Unit tests for encoding/decoding transformations."""

from lewaf.primitives.transformations import (
    base64_decode,
    css_js_decode,
    hex_decode,
    html_entity_decode,
    js_decode,
    url_decode,
    url_decode_uni,
)


def test_url_decode_transformation():
    """Test URL decoding transformation."""
    result, changed = url_decode("hello%20world")
    assert result == "hello world"
    assert changed is True

    result, changed = url_decode("test%3Dvalue")
    assert result == "test=value"
    assert changed is True

    result, changed = url_decode("no_encoding")
    assert result == "no_encoding"
    assert changed is False

    result, changed = url_decode("")
    assert result == ""
    assert changed is False


def test_url_decode_uni_transformation():
    """Test Unicode URL decoding transformation."""
    result, changed = url_decode_uni("hello+world")
    assert result == "hello world"
    assert changed is True

    result, changed = url_decode_uni("test%20value")
    assert result == "test value"
    assert changed is True

    result, changed = url_decode_uni("normal_text")
    assert result == "normal_text"
    assert changed is False


def test_html_entity_decode_transformation():
    """Test HTML entity decoding transformation."""
    result, changed = html_entity_decode("&lt;script&gt;")
    assert result == "<script>"
    assert changed is True

    result, changed = html_entity_decode("&amp;nbsp;&quot;")
    assert result == '&nbsp;"'
    assert changed is True

    result, changed = html_entity_decode("no entities")
    assert result == "no entities"
    assert changed is False

    result, changed = html_entity_decode("")
    assert result == ""
    assert changed is False


def test_js_decode_transformation():
    """Test JavaScript decoding transformation."""
    result, changed = js_decode("\\x41\\x42\\x43")
    assert result == "ABC"
    assert changed is True

    result, changed = js_decode("\\u0041\\u0042\\u0043")
    assert result == "ABC"
    assert changed is True

    result, changed = js_decode('\\"test\\"')
    assert result == '"test"'
    assert changed is True

    result, changed = js_decode("\\n\\r\\t")
    assert result == "\n\r\t"
    assert changed is True

    result, changed = js_decode("normal text")
    assert result == "normal text"
    assert changed is False


def test_css_js_decode_transformation():
    """Test combined CSS and JavaScript decoding."""
    result, changed = css_js_decode("\\41 BC")  # CSS hex + normal
    assert result == "ABC"
    assert changed is True

    result, changed = css_js_decode("\\x41\\x42\\x43")  # JS hex
    assert result == "ABC"
    assert changed is True

    result, changed = css_js_decode("normal text")
    assert result == "normal text"
    assert changed is False


def test_base64_decode_transformation():
    """Test Base64 decoding transformation."""
    result, changed = base64_decode("SGVsbG8gV29ybGQ=")
    assert result == "Hello World"
    assert changed is True

    result, changed = base64_decode("SGVsbG8gV29ybGQ")  # Missing padding
    assert result == "Hello World"
    assert changed is True

    result, changed = base64_decode("invalid!!!base64")
    assert result == "invalid!!!base64"  # Returns original on error
    assert changed is False

    result, changed = base64_decode("")
    assert result == ""
    assert changed is False


def test_hex_decode_transformation():
    """Test hexadecimal decoding transformation."""
    result, changed = hex_decode("48656c6c6f")
    assert result == "Hello"
    assert changed is True

    result, changed = hex_decode("414243")
    assert result == "ABC"
    assert changed is True

    result, changed = hex_decode("48 65 6c 6c 6f")  # With spaces
    assert result == "Hello"
    assert changed is True

    result, changed = hex_decode("invalid_hex")
    assert result == "invalid_hex"  # Returns original on error
    assert changed is False

    result, changed = hex_decode("12345")  # Odd length
    assert result == "12345"  # Returns original on error
    assert changed is False


def test_encoding_transformations_edge_cases():
    """Test encoding transformations with edge cases."""
    # Empty inputs
    result, changed = url_decode("")
    assert result == ""
    assert changed is False

    result, changed = html_entity_decode("")
    assert result == ""
    assert changed is False

    result, changed = js_decode("")
    assert result == ""
    assert changed is False

    # Invalid inputs
    result, changed = base64_decode("!!!")
    assert result == "!!!"
    assert changed is False

    result, changed = hex_decode("ZZ")
    assert result == "ZZ"
    assert changed is False


def test_encoding_transformations_with_special_characters():
    """Test encoding transformations with special characters."""
    # URL encode special chars
    result, changed = url_decode("test%21%40%23")
    assert result == "test!@#"
    assert changed is True

    # HTML entities with special chars
    result, changed = html_entity_decode("&lt;test&gt;&amp;&quot;")
    assert result == '<test>&"'
    assert changed is True

    # JavaScript with special escapes
    result, changed = js_decode(r"\\test\\")
    assert result == "\test\\"  # Backslash escapes are decoded
    assert changed is True


def test_encoding_transformations_unicode():
    """Test encoding transformations with Unicode."""
    # Base64 with Unicode
    unicode_b64 = "Q2Fmw6k="  # "Café" in base64
    result, changed = base64_decode(unicode_b64)
    assert "Caf" in result  # Should contain the decoded content
    assert changed is True

    # Hex with Unicode bytes
    unicode_hex = "43616665cc81"  # "Café" in hex
    result, changed = hex_decode(unicode_hex)
    assert len(result) > 0
    assert changed is True
