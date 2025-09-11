import base64
import hashlib
import html
import re
from typing import Tuple
from urllib.parse import unquote, unquote_plus

TRANSFORMATIONS = {}


def register_transformation(name: str):
    """Register a transformation function by name."""

    def decorator(fn):
        TRANSFORMATIONS[name.lower()] = fn
        return fn

    return decorator


@register_transformation("lowercase")
def lowercase(value: str) -> Tuple[str, bool]:
    """Transform string to lowercase."""
    lower_val = value.lower()
    return lower_val, lower_val != value


@register_transformation("uppercase")
def uppercase(value: str) -> Tuple[str, bool]:
    """Transform string to uppercase."""
    upper_val = value.upper()
    return upper_val, upper_val != value


@register_transformation("length")
def length(value: str) -> Tuple[str, bool]:
    """Return the length of the string as a string."""
    return str(len(value)), True  # Always considered changed


@register_transformation("trim")
def trim(value: str) -> Tuple[str, bool]:
    """Remove leading and trailing whitespace."""
    trimmed = value.strip()
    return trimmed, trimmed != value


@register_transformation("compresswhitespace")
def compress_whitespace(value: str) -> Tuple[str, bool]:
    """Replace multiple consecutive whitespace characters with a single space."""
    import re

    compressed = re.sub(r"\s+", " ", value)
    return compressed, compressed != value


@register_transformation("removewhitespace")
def remove_whitespace(value: str) -> Tuple[str, bool]:
    """Remove all whitespace characters."""
    removed = re.sub(r"\s", "", value)
    return removed, removed != value


@register_transformation("urldecode")
def url_decode(value: str) -> Tuple[str, bool]:
    """URL decode the input string."""
    decoded = unquote(value)
    return decoded, decoded != value


@register_transformation("urldecodeuni")
def url_decode_uni(value: str) -> Tuple[str, bool]:
    """URL decode with unicode handling."""
    try:
        decoded = unquote_plus(value)
        return decoded, decoded != value
    except UnicodeDecodeError:
        return value, False


@register_transformation("htmlentitydecode")
def html_entity_decode(value: str) -> Tuple[str, bool]:
    """Decode HTML entities."""
    decoded = html.unescape(value)
    return decoded, decoded != value


@register_transformation("jsdecode")
def js_decode(value: str) -> Tuple[str, bool]:
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
def css_js_decode(value: str) -> Tuple[str, bool]:
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
def base64_decode(value: str) -> Tuple[str, bool]:
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
def hex_decode(value: str) -> Tuple[str, bool]:
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
def md5_hash(value: str) -> Tuple[str, bool]:
    """Calculate MD5 hash of the input."""
    hash_obj = hashlib.md5(value.encode("utf-8"))
    return hash_obj.hexdigest(), True  # Always changed


@register_transformation("sha1")
def sha1_hash(value: str) -> Tuple[str, bool]:
    """Calculate SHA1 hash of the input."""
    hash_obj = hashlib.sha1(value.encode("utf-8"))
    return hash_obj.hexdigest(), True  # Always changed


@register_transformation("sha256")
def sha256_hash(value: str) -> Tuple[str, bool]:
    """Calculate SHA256 hash of the input."""
    hash_obj = hashlib.sha256(value.encode("utf-8"))
    return hash_obj.hexdigest(), True  # Always changed


@register_transformation("normalizepath")
def normalize_path(value: str) -> Tuple[str, bool]:
    """Normalize file path by resolving .. and . components."""
    import os.path

    try:
        normalized = os.path.normpath(value)
        # Replace backslashes with forward slashes for consistency
        normalized = normalized.replace("\\", "/")
        return normalized, normalized != value
    except Exception:
        return value, False


@register_transformation("removenulls")
def remove_nulls(value: str) -> Tuple[str, bool]:
    """Remove null bytes from string."""
    cleaned = value.replace("\x00", "")
    return cleaned, cleaned != value


@register_transformation("replacecomments")
def replace_comments(value: str) -> Tuple[str, bool]:
    """Replace SQL/C-style comments with spaces."""
    # Replace /* ... */ comments
    replaced = re.sub(r"/\*.*?\*/", " ", value, flags=re.DOTALL)
    # Replace -- comments (SQL)
    replaced = re.sub(r"--.*?$", " ", replaced, flags=re.MULTILINE)
    # Replace # comments
    replaced = re.sub(r"#.*?$", " ", replaced, flags=re.MULTILINE)
    # Replace // comments
    replaced = re.sub(r"//.*?$", " ", replaced, flags=re.MULTILINE)

    return replaced, replaced != value


@register_transformation("removenullbytes")
def remove_null_bytes(value: str) -> Tuple[str, bool]:
    """Remove null bytes and other control characters."""
    # Remove null bytes and other problematic control characters
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    return cleaned, cleaned != value


@register_transformation("replacewhitespace")
def replace_whitespace(value: str) -> Tuple[str, bool]:
    """Replace whitespace characters with spaces."""
    replaced = re.sub(r"\s", " ", value)
    return replaced, replaced != value
