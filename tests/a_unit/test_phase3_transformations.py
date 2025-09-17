"""Tests for Phase 3 transformation features: encoding/decoding, text processing, and path normalization."""

from __future__ import annotations


from coraza_poc.primitives.transformations import (
    # Encoding/Decoding
    base64_decode_ext,
    base64_encode,
    hex_encode,
    url_encode,
    utf8_to_unicode,
    # Text Processing
    cmd_line,
    css_decode,
    escape_seq_decode,
    remove_comments,
    remove_comments_char,
    trim_left,
    trim_right,
    # Path Normalization
    normalise_path,
    normalise_path_win,
    normalize_path_win,
    # Verify registration
    TRANSFORMATIONS,
)


class TestEncodingDecodingTransformations:
    """Test Phase 3 encoding/decoding transformations."""

    def test_base64_decode_ext_forgiving(self):
        """Test base64DecodeExt with forgiving implementation."""
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

        # Invalid input
        result, changed = base64_decode_ext("!!!")
        assert result == "!!!"
        assert changed is False

    def test_base64_encode(self):
        """Test base64Encode transformation."""
        result, changed = base64_encode("Hello World")
        assert result == "SGVsbG8gV29ybGQ="
        assert changed is True

        # Test with special characters
        result, changed = base64_encode("Test with spaces & symbols!")
        assert result == "VGVzdCB3aXRoIHNwYWNlcyAmIHN5bWJvbHMh"
        assert changed is True

        # Empty string
        result, changed = base64_encode("")
        assert result == ""
        assert changed is True

    def test_hex_encode(self):
        """Test hexEncode transformation."""
        result, changed = hex_encode("ABC")
        assert result == "414243"
        assert changed is True

        result, changed = hex_encode("Hello")
        assert result == "48656c6c6f"
        assert changed is True

        # Test with Unicode
        result, changed = hex_encode("Test™")
        assert result.startswith("54657374")  # "Test" part
        assert changed is True

        # Empty string
        result, changed = hex_encode("")
        assert result == ""
        assert changed is True

    def test_url_encode(self):
        """Test urlEncode transformation."""
        result, changed = url_encode("Hello World")
        assert result == "Hello%20World"
        assert changed is True

        result, changed = url_encode("test@example.com")
        assert result == "test%40example.com"
        assert changed is True

        # Special characters
        result, changed = url_encode("a=b&c=d")
        assert result == "a%3Db%26c%3Dd"
        assert changed is True

        # No encoding needed
        result, changed = url_encode("test")
        assert result == "test"
        assert changed is False

    def test_utf8_to_unicode(self):
        """Test utf8toUnicode transformation."""
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

        # Empty string
        result, changed = utf8_to_unicode("")
        assert result == ""
        assert changed is False


class TestTextProcessingTransformations:
    """Test Phase 3 text processing transformations."""

    def test_cmd_line_evasion_removal(self):
        """Test cmdLine transformation removes evasion characters."""
        # Basic command line evasion
        result, changed = cmd_line('c^ommand /c "test"')
        assert result == "command/c test"
        assert changed is True

        # Complex evasion (tab before slash should be removed)
        result, changed = cmd_line('com\\mand, /c \t"test"')
        assert result == "command/c test"
        assert changed is True

        # Spaces before slash and parenthesis (according to spec, spaces before / should be removed)
        result, changed = cmd_line("cmd  /c test  (something)")
        assert result == "cmd/c test(something)"
        assert changed is True

        # Semicolons and commas
        result, changed = cmd_line("cmd;echo,test")
        assert result == "cmd echo test"
        assert changed is True

        # Multiple spaces and case conversion
        result, changed = cmd_line("  CMD   /C   TEST  ")
        assert result == "cmd/c test"
        assert changed is True

    def test_css_decode(self):
        """Test cssDecode transformation."""
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

    def test_escape_seq_decode(self):
        """Test escapeSeqDecode for ANSI C escape sequences."""
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

        # No escape sequences
        result, changed = escape_seq_decode("normal text")
        assert result == "normal text"
        assert changed is False

    def test_remove_comments(self):
        """Test removeComments transformation."""
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

        # No comments
        result, changed = remove_comments("normal code")
        assert result == "normal code"
        assert changed is False

    def test_remove_comments_char(self):
        """Test removeCommentsChar transformation."""
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

        # No comment chars
        result, changed = remove_comments_char("normal text")
        assert result == "normal text"
        assert changed is False

    def test_trim_left(self):
        """Test trimLeft transformation."""
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

        # All whitespace
        result, changed = trim_left("   ")
        assert result == ""
        assert changed is True

    def test_trim_right(self):
        """Test trimRight transformation."""
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

        # All whitespace
        result, changed = trim_right("   ")
        assert result == ""
        assert changed is True


class TestPathNormalizationTransformations:
    """Test Phase 3 path normalization transformations."""

    def test_normalise_path_british_spelling(self):
        """Test normalisePath (British spelling) transformation."""
        # Should work the same as normalizePath
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

    def test_normalise_path_win(self):
        """Test normalisePathWin transformation."""
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

    def test_normalize_path_win_american_spelling(self):
        """Test normalizePathWin (American spelling) transformation."""
        # Should work the same as normalisePathWin
        result, changed = normalize_path_win("C:\\Windows\\System32\\..\\drivers")
        expected = "C:/Windows/drivers"
        assert result == expected
        assert changed is True


class TestPhase3TransformationRegistry:
    """Test that all Phase 3 transformations are properly registered."""

    def test_encoding_decoding_registered(self):
        """Test encoding/decoding transformations are registered."""
        assert "base64decodeext" in TRANSFORMATIONS
        assert "base64encode" in TRANSFORMATIONS
        assert "hexencode" in TRANSFORMATIONS
        assert "urlencode" in TRANSFORMATIONS
        assert "utf8tounicode" in TRANSFORMATIONS

    def test_text_processing_registered(self):
        """Test text processing transformations are registered."""
        assert "cmdline" in TRANSFORMATIONS
        assert "cssdecode" in TRANSFORMATIONS
        assert "escapeseqdecode" in TRANSFORMATIONS
        assert "removecomments" in TRANSFORMATIONS
        assert "removecommentschar" in TRANSFORMATIONS
        assert "trimleft" in TRANSFORMATIONS
        assert "trimright" in TRANSFORMATIONS

    def test_path_normalization_registered(self):
        """Test path normalization transformations are registered."""
        assert "normalisepath" in TRANSFORMATIONS
        assert "normalisepathwin" in TRANSFORMATIONS
        assert "normalizepathwin" in TRANSFORMATIONS


class TestPhase3CRSIntegration:
    """Test Phase 3 transformations with CRS-style usage."""

    def test_transformation_chaining(self):
        """Test Phase 3 transformations work in chains."""
        # Simulate a transformation chain: base64decode -> cmdline -> lowercase
        input_data = "Y21kIC9jIGVjaG8gdGVzdA=="  # base64 of "cmd /c echo test"

        # Step 1: base64DecodeExt
        result, _ = base64_decode_ext(input_data)
        assert result == "cmd /c echo test"

        # Step 2: cmdLine
        result, _ = cmd_line(result)
        assert result == "cmd/c echo test"

        # This demonstrates how transformations chain together

    def test_evasion_detection(self):
        """Test that Phase 3 transformations help detect evasions."""
        # CSS evasion
        evasion1 = "\\6a\\61\\76\\61\\73\\63\\72\\69\\70\\74"  # "javascript" in CSS hex
        result, _ = css_decode(evasion1)
        assert result == "javascript"

        # Command line evasion
        evasion2 = 'c^md /c "echo test"'
        result, _ = cmd_line(evasion2)
        assert result == "cmd/c echo test"

        # Unicode evasion
        evasion3 = "Tëst"
        result, _ = utf8_to_unicode(evasion3)
        assert "\\u" in result

    def test_complex_transformation_scenarios(self):
        """Test complex real-world transformation scenarios."""
        # Base64 encoded command with evasion
        encoded_cmd = "Y21kIC9jICJlY2hvIHRlc3QiIA=="

        # Decode first
        decoded, _ = base64_decode_ext(encoded_cmd)

        # Then normalize command line
        normalized, _ = cmd_line(decoded)

        # Should result in clean command
        assert "cmd" in normalized.lower()
        assert "echo" in normalized.lower()

    def test_path_traversal_normalization(self):
        """Test path normalization helps detect traversal attacks."""
        # Windows path traversal
        attack_path = "C:\\inetpub\\wwwroot\\..\\..\\windows\\system32\\cmd.exe"
        normalized, _ = normalise_path_win(attack_path)

        # Should normalize to expose the traversal
        assert "windows/system32/cmd.exe" in normalized.lower()

        # Unix path traversal
        attack_path2 = "/var/www/html/../../../../etc/passwd"
        normalized2, _ = normalise_path(attack_path2)

        # Should normalize path components
        assert "../" not in normalized2 or normalized2.count(
            "../"
        ) < attack_path2.count("../")
