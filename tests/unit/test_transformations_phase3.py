"""Unit tests for Phase 3 transformations (advanced encoding, text processing, path normalization)."""

from lewaf.primitives.transformations import (
    base64_decode_ext,
    base64_encode,
    hex_encode,
    url_encode,
    utf8_to_unicode,
    cmd_line,
    css_decode,
    escape_seq_decode,
    remove_comments,
    remove_comments_char,
    trim_left,
    trim_right,
    normalise_path,
    normalise_path_win,
    normalize_path_win,
)


def test_base64_decode_ext_forgiving():
    """Test extended Base64 decoding with forgiving implementation."""
    # Standard base64
    result, changed = base64_decode_ext("SGVsbG8gV29ybGQ=")
    assert result == "Hello World"
    assert changed is True

    # Missing padding (should be forgiving)
    result, changed = base64_decode_ext("SGVsbG8gV29ybGQ")
    assert result == "Hello World"
    assert changed is True

    # With invalid characters (should ignore them)
    result, changed = base64_decode_ext("SGVsb@G8g*V29y[bGQ=")
    assert result == "Hello World"
    assert changed is True

    # Empty/whitespace only
    result, changed = base64_decode_ext("   ")
    assert result == "   "
    assert changed is False


def test_base64_encode():
    """Test Base64 encoding transformation."""
    result, changed = base64_encode("Hello World")
    assert result == "SGVsbG8gV29ybGQ="
    assert changed is True

    result, changed = base64_encode("Test with spaces & symbols!")
    assert result == "VGVzdCB3aXRoIHNwYWNlcyAmIHN5bWJvbHMh"
    assert changed is True

    result, changed = base64_encode("")
    assert result == ""
    assert changed is True


def test_hex_encode():
    """Test hexadecimal encoding transformation."""
    result, changed = hex_encode("ABC")
    assert result == "414243"
    assert changed is True

    result, changed = hex_encode("Hello")
    assert result == "48656c6c6f"
    assert changed is True

    result, changed = hex_encode("")
    assert result == ""
    assert changed is True


def test_url_encode():
    """Test URL encoding transformation."""
    result, changed = url_encode("Hello World")
    assert result == "Hello%20World"
    assert changed is True

    result, changed = url_encode("test@example.com")
    assert result == "test%40example.com"
    assert changed is True

    result, changed = url_encode("a=b&c=d")
    assert result == "a%3Db%26c%3Dd"
    assert changed is True

    result, changed = url_encode("test")
    assert result == "test"
    assert changed is False


def test_utf8_to_unicode():
    """Test UTF-8 to Unicode transformation."""
    # ASCII only - no change
    result, changed = utf8_to_unicode("Hello")
    assert result == "Hello"
    assert changed is False

    # Unicode characters
    result, changed = utf8_to_unicode("Café")
    assert "\\u00e9" in result  # é character
    assert changed is True

    # Mixed ASCII and Unicode
    result, changed = utf8_to_unicode("Test™")
    assert result.startswith("Test")
    assert "\\u2122" in result  # ™ character
    assert changed is True


def test_cmd_line_evasion_removal():
    """Test command line transformation removes evasion characters."""
    # Basic command line evasion
    result, changed = cmd_line('c^ommand /c "test"')
    assert result == "command/c test"
    assert changed is True

    # Complex evasion (tab before slash should be removed)
    result, changed = cmd_line('com\\mand, /c \t"test"')
    assert result == "command/c test"
    assert changed is True

    # Spaces before slash and parenthesis
    result, changed = cmd_line("cmd  /c test  (something)")
    assert result == "cmd/c test(something)"
    assert changed is True

    # Semicolons and commas
    result, changed = cmd_line("cmd;echo,test")
    assert result == "cmd echo test"
    assert changed is True


def test_css_decode():
    """Test CSS decoding transformation."""
    # Basic CSS hex escape
    result, changed = css_decode("\\41 BC")  # \41 = 'A'
    assert result == "ABC"
    assert changed is True

    # CSS escape with optional space
    result, changed = css_decode("\\41BC")
    assert result == "ABC"
    assert changed is True

    # Multiple escapes
    result, changed = css_decode("\\48\\65\\6c\\6c\\6f")  # "Hello"
    assert result == "Hello"
    assert changed is True

    # Non-hex character escapes (ja\vascript)
    result, changed = css_decode("ja\\vascript")
    assert result == "javascript"
    assert changed is True

    # No CSS escapes
    result, changed = css_decode("normal text")
    assert result == "normal text"
    assert changed is False


def test_escape_seq_decode():
    """Test ANSI C escape sequence decoding."""
    # Basic escape sequences
    result, changed = escape_seq_decode("Hello\\nWorld")
    assert result == "Hello\nWorld"
    assert changed is True

    # Multiple escape types
    result, changed = escape_seq_decode("Test\\t\\r\\n")
    assert result == "Test\t\r\n"
    assert changed is True

    # Hex escapes
    result, changed = escape_seq_decode("\\x41\\x42\\x43")
    assert result == "ABC"
    assert changed is True

    # Octal escapes
    result, changed = escape_seq_decode("\\0101\\0102\\0103")  # ABC in octal
    assert result == "ABC"
    assert changed is True

    # Quotes and backslashes
    result, changed = escape_seq_decode('\\"test\\" \\\\')
    assert result == '"test" \\'
    assert changed is True


def test_remove_comments():
    """Test comment removal transformation."""
    # C-style comments
    result, changed = remove_comments("code /* comment */ more")
    assert result == "code  more"
    assert changed is True

    # SQL comments
    result, changed = remove_comments("SELECT * FROM table -- comment")
    assert result == "SELECT * FROM table "
    assert changed is True

    # Hash comments
    result, changed = remove_comments("script # comment\nmore code")
    assert result == "script \nmore code"
    assert changed is True

    # Mixed comments
    result, changed = remove_comments("code /* block */ -- line\nmore")
    assert result == "code  \nmore"
    assert changed is True


def test_remove_comments_char():
    """Test comment character removal transformation."""
    # Remove comment characters
    result, changed = remove_comments_char("code /*comment*/ more")
    assert result == "code comment more"
    assert changed is True

    # Remove SQL comment chars
    result, changed = remove_comments_char("SELECT * -- comment")
    assert result == "SELECT *  comment"
    assert changed is True

    # Remove hash
    result, changed = remove_comments_char("test # comment")
    assert result == "test  comment"
    assert changed is True


def test_trim_left():
    """Test left trimming transformation."""
    result, changed = trim_left("   hello world")
    assert result == "hello world"
    assert changed is True

    result, changed = trim_left("\t\n  test")
    assert result == "test"
    assert changed is True

    # No leading whitespace
    result, changed = trim_left("hello world   ")
    assert result == "hello world   "
    assert changed is False


def test_trim_right():
    """Test right trimming transformation."""
    result, changed = trim_right("hello world   ")
    assert result == "hello world"
    assert changed is True

    result, changed = trim_right("test  \t\n")
    assert result == "test"
    assert changed is True

    # No trailing whitespace
    result, changed = trim_right("   hello world")
    assert result == "   hello world"
    assert changed is False


def test_normalise_path_british_spelling():
    """Test path normalization with British spelling."""
    result, changed = normalise_path("/path/to/../file")
    assert result == "/path/file"
    assert changed is True

    result, changed = normalise_path("./relative/path")
    assert result == "relative/path"
    assert changed is True

    # No normalization needed
    result, changed = normalise_path("/simple/path")
    assert result == "/simple/path"
    assert changed is False


def test_normalise_path_win():
    """Test Windows path normalization."""
    # Convert backslashes and normalize
    result, changed = normalise_path_win("C:\\path\\to\\..\\file")
    expected = "C:/path/file"
    assert result == expected
    assert changed is True

    # Mixed slashes
    result, changed = normalise_path_win("C:\\path/to\\file")
    assert "/" in result  # Should use forward slashes
    assert changed is True

    # Forward slashes only
    result, changed = normalise_path_win("/unix/path")
    assert result == "/unix/path"
    assert changed is False


def test_normalize_path_win_american_spelling():
    """Test Windows path normalization with American spelling."""
    result, changed = normalize_path_win("C:\\Windows\\System32\\..\\drivers")
    expected = "C:/Windows/drivers"
    assert result == expected
    assert changed is True


def test_phase3_transformations_edge_cases():
    """Test Phase 3 transformations with edge cases."""
    # Empty inputs
    result, changed = cmd_line("")
    assert result == ""
    assert changed is False

    result, changed = css_decode("")
    assert result == ""
    assert changed is False

    result, changed = escape_seq_decode("")
    assert result == ""
    assert changed is False

    # Complex combinations
    result, changed = cmd_line('c^md;echo "test",/c')
    assert "cmd echo test/c" in result
    assert changed is True


def test_phase3_transformations_security_scenarios():
    """Test Phase 3 transformations with security-relevant scenarios."""
    # Command injection evasion
    evasion = 'c^md /c "echo test"'
    result, changed = cmd_line(evasion)
    assert result == "cmd/c echo test"
    assert changed is True

    # CSS evasion (javascript in CSS hex)
    css_evasion = "\\6a\\61\\76\\61\\73\\63\\72\\69\\70\\74"
    result, changed = css_decode(css_evasion)
    assert result == "javascript"
    assert changed is True

    # Base64 attack payload
    b64_attack = (
        "PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg=="  # <img src=x onerror=alert(1)>
    )
    result, changed = base64_decode_ext(b64_attack)
    assert "img" in result
    assert "onerror" in result
    assert changed is True
