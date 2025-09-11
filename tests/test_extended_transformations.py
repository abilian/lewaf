"""Tests for extended transformations matching Go Coraza functionality."""

import base64

from coraza_poc.primitives.transformations import (
    base64_decode,
    css_js_decode,
    hex_decode,
    html_entity_decode,
    js_decode,
    md5_hash,
    normalize_path,
    remove_null_bytes,
    remove_nulls,
    replace_comments,
    replace_whitespace,
    sha1_hash,
    sha256_hash,
    url_decode,
    url_decode_uni,
)


def test_url_decode_transformation():
    """Test URL decoding transformation."""
    # Basic URL decoding
    result, changed = url_decode("Hello%20World")
    assert result == "Hello World"
    assert changed is True

    # Special characters
    result, changed = url_decode("user%40example.com")
    assert result == "user@example.com"
    assert changed is True

    # No change needed
    result, changed = url_decode("HelloWorld")
    assert result == "HelloWorld"
    assert changed is False

    # Plus signs
    result, changed = url_decode("Hello+World")
    assert result == "Hello+World"  # unquote doesn't decode +
    assert changed is False


def test_url_decode_uni_transformation():
    """Test Unicode URL decoding transformation."""
    # Plus to space conversion
    result, changed = url_decode_uni("Hello+World")
    assert result == "Hello World"
    assert changed is True

    # Regular URL encoding
    result, changed = url_decode_uni("Hello%20World")
    assert result == "Hello World"
    assert changed is True

    # No change
    result, changed = url_decode_uni("HelloWorld")
    assert result == "HelloWorld"
    assert changed is False


def test_html_entity_decode_transformation():
    """Test HTML entity decoding transformation."""
    # Named entities
    result, changed = html_entity_decode(
        "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;"
    )
    assert result == '<script>alert("xss")</script>'
    assert changed is True

    # Numeric entities
    result, changed = html_entity_decode("&#60;&#62;")
    assert result == "<>"
    assert changed is True

    # Common entities
    result, changed = html_entity_decode("&amp;&nbsp;&copy;")
    assert result == "&\xa0©"
    assert changed is True

    # No change
    result, changed = html_entity_decode("normal text")
    assert result == "normal text"
    assert changed is False


def test_js_decode_transformation():
    """Test JavaScript decoding transformation."""
    # Hex escapes
    result, changed = js_decode(r"\x41\x42\x43")
    assert result == "ABC"
    assert changed is True

    # Unicode escapes
    result, changed = js_decode(r"\u0041\u0042\u0043")
    assert result == "ABC"
    assert changed is True

    # Basic escapes
    result, changed = js_decode(r"\"Hello\"\n\r\t\\")
    assert result == '"Hello"\n\r\t\\'
    assert changed is True

    # Single quotes
    result, changed = js_decode(r"\'test\'")
    assert result == "'test'"
    assert changed is True

    # No change
    result, changed = js_decode("normal text")
    assert result == "normal text"
    assert changed is False


def test_css_js_decode_transformation():
    """Test CSS and JavaScript combined decoding."""
    # CSS hex escapes (with spaces they become separate chars)
    result, changed = css_js_decode(r"\41\42\43")
    assert result == "ABC"
    assert changed is True

    # Combined CSS and JS
    result, changed = css_js_decode(r"\41\x42\u0043")
    assert result == "ABC"
    assert changed is True

    # No change
    result, changed = css_js_decode("normal text")
    assert result == "normal text"
    assert changed is False


def test_base64_decode_transformation():
    """Test base64 decoding transformation."""
    # Standard base64
    encoded = base64.b64encode(b"Hello World").decode("ascii")
    result, changed = base64_decode(encoded)
    assert result == "Hello World"
    assert changed is True

    # Base64 without padding
    result, changed = base64_decode("SGVsbG8")  # "Hello" without padding
    assert result == "Hello"
    assert changed is True

    # Invalid base64 (should return original value)
    result, changed = base64_decode("invalid base64!")
    assert result == "invalid base64!"
    assert changed is False

    # Empty string
    result, changed = base64_decode("")
    assert result == ""
    assert changed is False


def test_hex_decode_transformation():
    """Test hexadecimal decoding transformation."""
    # Basic hex
    result, changed = hex_decode("48656c6c6f")  # "Hello"
    assert result == "Hello"
    assert changed is True

    # Upper case hex
    result, changed = hex_decode("48656C6C6F")
    assert result == "Hello"
    assert changed is True

    # With spaces (should be removed)
    result, changed = hex_decode("48 65 6c 6c 6f")
    assert result == "Hello"
    assert changed is True

    # Odd length (invalid)
    result, changed = hex_decode("48656c6c6")
    assert result == "48656c6c6"
    assert changed is False

    # Invalid hex (all letters are valid hex, so this becomes empty)
    result, changed = hex_decode("zxy123")  # z, x, y are not hex digits
    assert result == "zxy123"  # Should return original since no valid hex
    assert changed is False


def test_hash_transformations():
    """Test hash transformations."""
    test_input = "Hello World"

    # MD5
    result, changed = md5_hash(test_input)
    assert len(result) == 32  # MD5 is 32 hex characters
    assert changed is True

    # SHA1
    result, changed = sha1_hash(test_input)
    assert len(result) == 40  # SHA1 is 40 hex characters
    assert changed is True

    # SHA256
    result, changed = sha256_hash(test_input)
    assert len(result) == 64  # SHA256 is 64 hex characters
    assert changed is True

    # Verify actual hash values
    md5_result, _ = md5_hash("test")
    assert md5_result == "098f6bcd4621d373cade4e832627b4f6"


def test_normalize_path_transformation():
    """Test path normalization transformation."""
    # Basic path normalization
    result, changed = normalize_path("/path/../other/./file")
    assert result == "/other/file"
    assert changed is True

    # Backslash conversion
    result, changed = normalize_path("path\\to\\file")
    assert result == "path/to/file"
    assert changed is True

    # Multiple dots
    result, changed = normalize_path("/path/../../root")
    assert result == "/root"
    assert changed is True

    # No change needed
    result, changed = normalize_path("/simple/path")
    assert result == "/simple/path"
    assert changed is False


def test_remove_nulls_transformation():
    """Test null byte removal transformation."""
    # Null bytes
    result, changed = remove_nulls("Hello\x00World")
    assert result == "HelloWorld"
    assert changed is True

    # Multiple null bytes
    result, changed = remove_nulls("Test\x00\x00Data")
    assert result == "TestData"
    assert changed is True

    # No null bytes
    result, changed = remove_nulls("Normal text")
    assert result == "Normal text"
    assert changed is False


def test_remove_null_bytes_transformation():
    """Test control character removal transformation."""
    # Various control characters
    result, changed = remove_null_bytes("Hello\x00\x01\x08World\x7f")
    assert result == "HelloWorld"
    assert changed is True

    # Keep allowed characters (tab, newline, carriage return)
    result, changed = remove_null_bytes("Hello\tWorld\n")
    assert result == "Hello\tWorld\n"
    assert changed is False

    # No control characters
    result, changed = remove_null_bytes("Normal text")
    assert result == "Normal text"
    assert changed is False


def test_replace_comments_transformation():
    """Test comment replacement transformation."""
    # C-style comments
    result, changed = replace_comments("SELECT * FROM /* comment */ users")
    assert result == "SELECT * FROM   users"
    assert changed is True

    # SQL comments
    result, changed = replace_comments("SELECT * FROM users -- comment")
    assert result == "SELECT * FROM users  "
    assert changed is True

    # Hash comments
    result, changed = replace_comments("echo 'test' # comment")
    assert result == "echo 'test'  "
    assert changed is True

    # JavaScript comments
    result, changed = replace_comments("var x = 1; // comment")
    assert result == "var x = 1;  "
    assert changed is True

    # Multiline comments
    result, changed = replace_comments("SELECT /*\nmultiline\ncomment\n*/ * FROM users")
    assert result == "SELECT   * FROM users"
    assert changed is True

    # No comments
    result, changed = replace_comments("normal text")
    assert result == "normal text"
    assert changed is False


def test_replace_whitespace_transformation():
    """Test whitespace replacement transformation."""
    # Various whitespace
    result, changed = replace_whitespace("Hello\tWorld\nTest")
    assert result == "Hello World Test"
    assert changed is True

    # Already spaces
    result, changed = replace_whitespace("Hello World Test")
    assert result == "Hello World Test"
    assert changed is False

    # Mixed whitespace
    result, changed = replace_whitespace("A\r\nB\tC")
    assert result == "A  B C"
    assert changed is True


def test_transformation_registry():
    """Test that all new transformations are registered."""
    from coraza_poc.primitives.transformations import TRANSFORMATIONS

    expected_transformations = [
        "urldecode",
        "urldecodeuni",
        "htmlentitydecode",
        "jsdecode",
        "cssjsdecode",
        "base64decode",
        "hexdecode",
        "md5",
        "sha1",
        "sha256",
        "normalizepath",
        "removenulls",
        "removenullbytes",
        "replacecomments",
        "replacewhitespace",
    ]

    for transform in expected_transformations:
        assert transform in TRANSFORMATIONS, (
            f"Transformation {transform} not registered"
        )


def test_transformation_change_detection():
    """Test that transformations correctly detect when changes are made."""
    # Transformations that should always report changes
    always_changed = [md5_hash, sha1_hash, sha256_hash]

    for transform in always_changed:
        result, changed = transform("test")
        assert changed is True, (
            f"Transform {transform.__name__} should always report changed=True"
        )

    # Transformations that should detect no change
    no_change_tests = [
        (url_decode, "no_encoding_needed"),
        (html_entity_decode, "no_entities"),
        (js_decode, "no_js_escapes"),
        (normalize_path, "/already/normalized"),
        (remove_nulls, "no_null_bytes"),
    ]

    for transform, test_input in no_change_tests:
        result, changed = transform(test_input)
        assert result == test_input
        assert changed is False, (
            f"Transform {transform.__name__} should report changed=False for '{test_input}'"
        )
