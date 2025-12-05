from __future__ import annotations

import base64
import hashlib
import html
import os
import re
import string
from typing import TYPE_CHECKING
from urllib.parse import quote, unquote, unquote_plus

if TYPE_CHECKING:
    from collections.abc import Callable

TRANSFORMATIONS = {}


def register_transformation(name: str) -> Callable:
    """Register a transformation function by name."""

    def decorator(fn):
        TRANSFORMATIONS[name.lower()] = fn
        return fn

    return decorator


@register_transformation("none")
def none_transform(value: str) -> tuple[str, bool]:
    """No transformation - pass through unchanged."""
    return value, False


@register_transformation("lowercase")
def lowercase(value: str) -> tuple[str, bool]:
    """Transform string to lowercase."""
    lower_val = value.lower()
    return lower_val, lower_val != value


@register_transformation("uppercase")
def uppercase(value: str) -> tuple[str, bool]:
    """Transform string to uppercase."""
    upper_val = value.upper()
    return upper_val, upper_val != value


@register_transformation("length")
def length(value: str) -> tuple[str, bool]:
    """Return the length of the string as a string."""
    return str(len(value)), True  # Always considered changed


@register_transformation("trim")
def trim(value: str) -> tuple[str, bool]:
    """Remove leading and trailing whitespace."""
    trimmed = value.strip()
    return trimmed, trimmed != value


@register_transformation("compresswhitespace")
def compress_whitespace(value: str) -> tuple[str, bool]:
    """Replace multiple consecutive whitespace characters with a single space."""
    compressed = re.sub(r"\s+", " ", value)
    return compressed, compressed != value


@register_transformation("removewhitespace")
def remove_whitespace(value: str) -> tuple[str, bool]:
    """Remove all whitespace characters."""
    removed = re.sub(r"\s", "", value)
    return removed, removed != value


@register_transformation("urldecode")
def url_decode(value: str) -> tuple[str, bool]:
    """URL decode the input string."""
    decoded = unquote(value)
    return decoded, decoded != value


@register_transformation("urldecodeuni")
def url_decode_uni(value: str) -> tuple[str, bool]:
    """URL decode with unicode handling."""
    try:
        decoded = unquote_plus(value)
        return decoded, decoded != value
    except UnicodeDecodeError:
        return value, False


@register_transformation("htmlentitydecode")
def html_entity_decode(value: str) -> tuple[str, bool]:
    """Decode HTML entities."""
    decoded = html.unescape(value)
    return decoded, decoded != value


@register_transformation("jsdecode")
def js_decode(value: str) -> tuple[str, bool]:
    """Decode JavaScript escape sequences."""
    # Basic JavaScript decoding
    decoded = value

    # Handle \\x hex escapes
    decoded = re.sub(
        r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), decoded
    )

    # Handle \\u unicode escapes
    decoded = re.sub(
        r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), decoded
    )

    # Handle basic escapes
    decoded = decoded.replace('\\"', '"')
    decoded = decoded.replace("\\'", "'")
    decoded = decoded.replace("\\\\", "\\")
    decoded = decoded.replace("\\n", "\n")
    decoded = decoded.replace("\\r", "\r")
    decoded = decoded.replace("\\t", "\t")

    return decoded, decoded != value


@register_transformation("cssjsdecode")
def css_js_decode(value: str) -> tuple[str, bool]:
    """Decode CSS and JavaScript escape sequences."""
    original_value = value
    decoded = value

    # CSS hex escapes - handle optional trailing space more carefully
    def css_replacer(match):
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)  # Return original if can't decode

    decoded = re.sub(r"\\([0-9a-fA-F]{1,6})\s?", css_replacer, decoded)

    # Then apply JS decoding
    decoded, _ = js_decode(decoded)

    return decoded, decoded != original_value


@register_transformation("base64decode")
def base64_decode(value: str) -> tuple[str, bool]:
    """Decode base64 encoded string."""
    try:
        # Only add padding if we have non-empty value and it looks like base64
        test_value = value.strip()
        if not test_value:
            return value, False

        # Add padding if needed
        missing_padding = len(test_value) % 4
        if missing_padding:
            test_value += "=" * (4 - missing_padding)

        decoded_bytes = base64.b64decode(test_value, validate=True)
        decoded = decoded_bytes.decode("utf-8", errors="ignore")
        return decoded, True  # Always consider changed if successful
    except Exception:
        return value, False


@register_transformation("hexdecode")
def hex_decode(value: str) -> tuple[str, bool]:
    """Decode hexadecimal encoded string."""
    try:
        # Remove any spaces or separators
        clean_hex = re.sub(r"[^0-9a-fA-F]", "", value)
        if len(clean_hex) % 2 != 0 or not clean_hex:
            return value, False

        decoded_bytes = bytes.fromhex(clean_hex)
        decoded = decoded_bytes.decode("utf-8", errors="ignore")
        return decoded, True
    except Exception:
        return value, False


@register_transformation("md5")
def md5_hash(value: str) -> tuple[str, bool]:
    """Calculate MD5 hash of the input."""
    hash_obj = hashlib.md5(value.encode("utf-8"))
    return hash_obj.hexdigest(), True  # Always changed


@register_transformation("sha1")
def sha1_hash(value: str) -> tuple[str, bool]:
    """Calculate SHA1 hash of the input."""
    hash_obj = hashlib.sha1(value.encode("utf-8"))
    return hash_obj.hexdigest(), True  # Always changed


@register_transformation("sha256")
def sha256_hash(value: str) -> tuple[str, bool]:
    """Calculate SHA256 hash of the input."""
    hash_obj = hashlib.sha256(value.encode("utf-8"))
    return hash_obj.hexdigest(), True  # Always changed


@register_transformation("removenulls")
def remove_nulls(value: str) -> tuple[str, bool]:
    """Remove null bytes from string."""
    cleaned = value.replace("\x00", "")
    return cleaned, cleaned != value


@register_transformation("removenullbytes")
def remove_null_bytes(value: str) -> tuple[str, bool]:
    """Remove null bytes and other control characters."""
    # Remove null bytes and other problematic control characters
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    return cleaned, cleaned != value


@register_transformation("replacewhitespace")
def replace_whitespace(value: str) -> tuple[str, bool]:
    """Replace whitespace characters with spaces."""
    replaced = re.sub(r"\s", " ", value)
    return replaced, replaced != value


# Phase 3: Encoding/Decoding Enhancements


@register_transformation("base64decodeext")
def base64_decode_ext(value: str) -> tuple[str, bool]:
    """Extended Base64 decoding with forgiving implementation that ignores invalid characters."""
    try:
        # Remove non-base64 characters (forgiving implementation)
        clean_value = re.sub(r"[^A-Za-z0-9+/=]", "", value.strip())
        if not clean_value:
            return value, False

        # Add padding if needed
        missing_padding = len(clean_value) % 4
        if missing_padding:
            clean_value += "=" * (4 - missing_padding)

        decoded_bytes = base64.b64decode(clean_value, validate=False)  # Forgiving
        decoded = decoded_bytes.decode("utf-8", errors="ignore")
        return decoded, True  # Always consider changed if successful
    except Exception:
        return value, False


@register_transformation("base64encode")
def base64_encode(value: str) -> tuple[str, bool]:
    """Encode input string using Base64 encoding."""
    try:
        encoded_bytes = value.encode("utf-8")
        encoded = base64.b64encode(encoded_bytes).decode("ascii")
        return encoded, True  # Always changed
    except Exception:
        return value, False


@register_transformation("hexencode")
def hex_encode(value: str) -> tuple[str, bool]:
    """Encode string by replacing each input byte with two hexadecimal characters."""
    try:
        encoded_bytes = value.encode("utf-8")
        encoded = encoded_bytes.hex()
        return encoded, True  # Always changed
    except Exception:
        return value, False


@register_transformation("urlencode")
def url_encode(value: str) -> tuple[str, bool]:
    """Encode input string using URL encoding."""
    try:
        encoded = quote(value, safe="")
        return encoded, encoded != value
    except Exception:
        return value, False


@register_transformation("utf8tounicode")
def utf8_to_unicode(value: str) -> tuple[str, bool]:
    """Convert UTF-8 character sequences to Unicode for input normalization."""
    try:
        # Encode as UTF-8 bytes then decode back to get proper Unicode representation
        # This helps normalize non-English characters and minimize false positives
        normalized = value.encode("utf-8").decode("utf-8")

        # Convert to Unicode code point representation where helpful for analysis
        result = ""
        changed = False
        for char in normalized:
            if ord(char) > 127:  # Non-ASCII character
                # Convert to \uXXXX format for normalization
                result += f"\\u{ord(char):04x}"
                changed = True
            else:
                result += char

        return result, changed
    except Exception:
        return value, False


# Phase 3: Advanced Text Processing


@register_transformation("cmdline")
def cmd_line(value: str) -> tuple[str, bool]:
    """Parse command line arguments by removing evasion characters and normalizing."""
    original_value = value
    result = value

    # Delete all backslashes
    result = result.replace("\\", "")

    # Delete all quotes
    result = result.replace('"', "")
    result = result.replace("'", "")

    # Delete all carets (Windows command line escape character)
    result = result.replace("^", "")

    # Replace commas and semicolons with spaces
    result = result.replace(",", " ")
    result = result.replace(";", " ")

    # Replace multiple whitespace with single space
    result = re.sub(r"\s+", " ", result)

    # Delete spaces before slash (after normalization)
    result = re.sub(r"\s+/", "/", result)

    # Delete spaces before open parenthesis
    result = re.sub(r"\s+\(", "(", result)

    # Convert to lowercase
    result = result.lower()

    # Trim final result
    result = result.strip()

    return result, result != original_value


@register_transformation("cssdecode")
def css_decode(value: str) -> tuple[str, bool]:
    """Decode CSS 2.x escape rules. Uses up to two bytes in decoding process."""
    original_value = value
    result = ""
    i = 0

    while i < len(value):
        if value[i] == "\\" and i + 1 < len(value):
            # Look for hex escape sequence
            hex_start = i + 1
            hex_end = hex_start

            # Find hex digits (up to 6)
            while (
                hex_end < len(value)
                and hex_end - hex_start < 6
                and value[hex_end] in string.hexdigits
            ):
                hex_end += 1

            if hex_end > hex_start:  # Found hex digits
                hex_value = value[hex_start:hex_end]

                # Check if followed by whitespace (which terminates the sequence)
                whitespace_follows = hex_end < len(value) and value[hex_end].isspace()

                # If not terminated by whitespace, we need to be more conservative
                # According to CSS spec, limit should be 2 hex digits for 2-byte decoding
                # unless there's whitespace termination
                if not whitespace_follows:
                    # Limit to 2 hex digits max for ambiguous cases
                    if len(hex_value) > 2:
                        hex_value = hex_value[:2]
                        hex_end = hex_start + 2

                try:
                    code_point = int(hex_value, 16)
                    if code_point <= 0xFFFF:  # 2-byte limit
                        result += chr(code_point)
                        i = hex_end
                        # Skip optional whitespace after hex escape
                        if i < len(value) and value[i].isspace():
                            i += 1
                        continue
                except (ValueError, OverflowError):
                    pass

            # Handle non-hex escape or invalid hex
            if i + 1 < len(value) and value[i + 1] not in string.hexdigits:
                # Non-hex character escape (e.g., ja\vascript -> javascript)
                result += value[i + 1]
                i += 2
                continue

            # If we get here, just add the backslash
            result += value[i]
            i += 1
        else:
            result += value[i]
            i += 1

    return result, result != original_value


@register_transformation("escapeseqdecode")
def escape_seq_decode(value: str) -> tuple[str, bool]:
    r"""Decode ANSI C escape sequences (\a, \b, \f, \n, \r, \t, \v, \\, \?, \', \", \xHH, \0OOO)."""
    original_value = value
    result = value

    # Standard ANSI C escape sequences
    escape_map = {
        "\\a": "\a",  # Alert (bell)
        "\\b": "\b",  # Backspace
        "\\f": "\f",  # Form feed
        "\\n": "\n",  # Newline
        "\\r": "\r",  # Carriage return
        "\\t": "\t",  # Tab
        "\\v": "\v",  # Vertical tab
        "\\\\": "\\",  # Backslash
        "\\?": "?",  # Question mark
        "\\'": "'",  # Single quote
        '\\"': '"',  # Double quote
    }

    # Replace standard escape sequences
    for escape_seq, replacement in escape_map.items():
        result = result.replace(escape_seq, replacement)

    # Handle hex escape sequences (\xHH)
    def hex_replacer(match):
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)  # Return original if invalid

    result = re.sub(r"\\x([0-9a-fA-F]{2})", hex_replacer, result)

    # Handle octal escape sequences (\0OOO)
    def octal_replacer(match):
        try:
            return chr(int(match.group(1), 8))
        except (ValueError, OverflowError):
            return match.group(0)  # Return original if invalid

    result = re.sub(r"\\0([0-7]{1,3})", octal_replacer, result)

    return result, result != original_value


@register_transformation("removecommentschar")
def remove_comments_char(value: str) -> tuple[str, bool]:
    """Remove common comment characters (/*,*/, --, #)."""
    original_value = value
    result = value

    # Remove comment character sequences
    result = result.replace("/*", "")
    result = result.replace("*/", "")
    result = result.replace("--", "")
    result = result.replace("#", "")

    return result, result != original_value


@register_transformation("trimleft")
def trim_left(value: str) -> tuple[str, bool]:
    """Remove whitespace from the left side of the input string."""
    trimmed = value.lstrip()
    return trimmed, trimmed != value


@register_transformation("trimright")
def trim_right(value: str) -> tuple[str, bool]:
    """Remove whitespace from the right side of the input string."""
    trimmed = value.rstrip()
    return trimmed, trimmed != value


# Phase 3: Path Normalization


@register_transformation("normalisepath")
def normalise_path(value: str) -> tuple[str, bool]:
    """Normalize file path by resolving .. and . components (British spelling)."""
    # Alias for normalize_path with British spelling
    return normalize_path(value)


@register_transformation("normalisepathwin")
def normalise_path_win(value: str) -> tuple[str, bool]:
    """Normalize Windows file path by converting backslashes and resolving path components."""
    original_value = value
    result = value

    # First convert backslashes to forward slashes
    result = result.replace("\\", "/")

    # Then normalize the path
    try:
        result = os.path.normpath(result)
        # Keep forward slashes for consistency
        result = result.replace("\\", "/")
    except Exception:
        pass  # If normpath fails, keep the backslash-converted version

    return result, result != original_value


@register_transformation("normalizepathwin")
def normalize_path_win(value: str) -> tuple[str, bool]:
    """Normalize Windows file path by converting backslashes and resolving path components."""
    # Same as normalise_path_win but with American spelling
    return normalise_path_win(value)


# Advanced Phase 6 Transformations


@register_transformation("sha1")
def sha1_transform(value: str) -> tuple[str, bool]:
    """Generate SHA-1 hash of the input value."""
    sha1_hash = hashlib.sha1(value.encode("utf-8")).hexdigest()
    return sha1_hash, True


@register_transformation("md5")
def md5_transform(value: str) -> tuple[str, bool]:
    """Generate MD5 hash of the input value."""
    md5_hash = hashlib.md5(value.encode("utf-8")).hexdigest()
    return md5_hash, True


@register_transformation("sha256")
def sha256_transform(value: str) -> tuple[str, bool]:
    """Generate SHA-256 hash of the input value."""
    sha256_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return sha256_hash, True


@register_transformation("replacecomments")
def replace_comments(value: str) -> tuple[str, bool]:
    """Replace common comment patterns with spaces.

    Removes SQL, C-style, and other comment patterns that might be used
    to evade detection in injection attacks.
    """
    original_value = value

    # SQL line comments
    value = re.sub(r"--[^\r\n]*", " ", value)

    # SQL block comments
    value = re.sub(r"/\*.*?\*/", " ", value, flags=re.DOTALL)

    # C-style line comments
    value = re.sub(r"//[^\r\n]*", " ", value)

    # Hash comments (shell style)
    value = re.sub(r"#[^\r\n]*", " ", value)

    # HTML comments
    value = re.sub(r"<!--.*?-->", " ", value, flags=re.DOTALL)

    return value, value != original_value


@register_transformation("replaceNulls")
def replace_nulls(value: str) -> tuple[str, bool]:
    """Replace null bytes and null-like patterns."""
    original_value = value

    # Replace null bytes
    value = value.replace("\x00", " ")

    # Replace common null representations
    value = re.sub(r"\\x00|\\0+|%00|&#0+;|&#x0+;", " ", value, flags=re.IGNORECASE)

    return value, value != original_value


@register_transformation("normalizePath")
def normalize_path(value: str) -> tuple[str, bool]:
    """Normalize file paths by resolving . and .. components and removing duplicates."""
    original_value = value

    # Split path into components
    components: list[str] = []
    for part in value.split("/"):
        if part == "" or part == ".":
            continue
        if part == "..":
            if components:
                components.pop()
        else:
            components.append(part)

    # Reconstruct path
    result = (
        "/" + "/".join(components) if value.startswith("/") else "/".join(components)
    )

    return result, result != original_value


@register_transformation("sqlHexDecode")
def sql_hex_decode(value: str) -> tuple[str, bool]:
    """Decode SQL hex encoding (0x48656c6c6f format)."""
    original_value = value

    def decode_hex_match(match):
        hex_value = match.group(1)
        try:
            # Convert hex to bytes then to string
            decoded_bytes = bytes.fromhex(hex_value)
            return decoded_bytes.decode("utf-8", errors="ignore")
        except (ValueError, UnicodeDecodeError):
            return match.group(0)  # Return original if decode fails

    # Match SQL hex literals like 0x48656c6c6f
    result = re.sub(r"0[xX]([0-9a-fA-F]+)", decode_hex_match, value)

    return result, result != original_value


@register_transformation("removeComments")
def remove_comments(value: str) -> tuple[str, bool]:
    """Remove common comment patterns entirely.

    Similar to replaceComments but removes comments completely instead
    of replacing with spaces.
    """
    original_value = value

    # SQL line comments
    value = re.sub(r"--[^\r\n]*", "", value)

    # SQL block comments
    value = re.sub(r"/\*.*?\*/", "", value, flags=re.DOTALL)

    # C-style line comments
    value = re.sub(r"//[^\r\n]*", "", value)

    # Hash comments
    value = re.sub(r"#[^\r\n]*", "", value)

    # HTML comments
    value = re.sub(r"<!--.*?-->", "", value, flags=re.DOTALL)

    return value, value != original_value


@register_transformation("parityEven7bit")
def parity_even_7bit(value: str) -> tuple[str, bool]:
    """Set even parity on 7-bit characters."""
    original_value = value
    result: list[str] = []

    for char in value:
        byte_val = ord(char)
        if byte_val < 128:  # 7-bit character
            # Count number of 1 bits
            ones_count = bin(byte_val).count("1")
            # Set parity bit to make total even
            if ones_count % 2 == 1:
                byte_val |= 0x80  # Set high bit
            else:
                byte_val &= 0x7F  # Clear high bit
        result.append(chr(byte_val))

    result_str = "".join(result)
    return result_str, result_str != original_value


@register_transformation("parityOdd7bit")
def parity_odd_7bit(value: str) -> tuple[str, bool]:
    """Set odd parity on 7-bit characters."""
    original_value = value
    result: list[str] = []

    for char in value:
        byte_val = ord(char)
        if byte_val < 128:  # 7-bit character
            # Count number of 1 bits
            ones_count = bin(byte_val).count("1")
            # Set parity bit to make total odd
            if ones_count % 2 == 0:
                byte_val |= 0x80  # Set high bit
            else:
                byte_val &= 0x7F  # Clear high bit
        result.append(chr(byte_val))

    result_str = "".join(result)
    return result_str, result_str != original_value


@register_transformation("parityZero7bit")
def parity_zero_7bit(value: str) -> tuple[str, bool]:
    """Clear parity bit (high bit) on all characters."""
    original_value = value
    result: list[str] = []

    for char in value:
        byte_val = ord(char) & 0x7F  # Clear high bit
        result.append(chr(byte_val))

    result_str = "".join(result)
    return result_str, result_str != original_value
