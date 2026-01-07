"""Property-based tests for transformations using Hypothesis.

These tests verify transformation correctness across a wide range of inputs:
1. Safety (no crashes on any input)
2. Idempotency (applying twice gives same result)
3. Reversibility (encode then decode returns original)
4. Length properties (predictable output lengths)
5. Hash properties (determinism and fixed output length)
"""

from __future__ import annotations

import string

from hypothesis import given, settings, strategies as st

from lewaf.primitives.transformations import TRANSFORMATIONS

# -----------------------------------------------------------------------------
# Strategies for generating test data
# -----------------------------------------------------------------------------

# Safe text without surrogate characters
safe_text = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=100)

# ASCII-only text for encoding tests
ascii_text = st.text(alphabet=string.printable, max_size=100)

# Binary-safe text (latin-1 decodable)
binary_safe_text = st.binary(max_size=100).map(lambda b: b.decode("latin-1"))

# Whitespace-containing text
whitespace_text = st.text(
    alphabet=st.sampled_from(" \t\n\r" + string.ascii_letters), max_size=50
)

# URL-safe characters
url_chars = string.ascii_letters + string.digits + "-_.~"


# -----------------------------------------------------------------------------
# Helper function to get transformation
# -----------------------------------------------------------------------------


def get_transform(name: str):
    """Get a transformation function by name."""
    return TRANSFORMATIONS.get(name.lower())


# -----------------------------------------------------------------------------
# Safety Properties: Transformations should never crash
# -----------------------------------------------------------------------------


@given(value=safe_text)
@settings(max_examples=100)
def test_lowercase_no_crash(value: str):
    """lowercase should never crash."""
    result, changed = get_transform("lowercase")(value)
    assert isinstance(result, str)
    assert isinstance(changed, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_uppercase_no_crash(value: str):
    """uppercase should never crash."""
    result, changed = get_transform("uppercase")(value)
    assert isinstance(result, str)
    assert isinstance(changed, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_trim_no_crash(value: str):
    """trim should never crash."""
    result, changed = get_transform("trim")(value)
    assert isinstance(result, str)
    assert isinstance(changed, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_length_no_crash(value: str):
    """length should never crash."""
    result, changed = get_transform("length")(value)
    assert isinstance(result, str)
    assert isinstance(changed, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_removewhitespace_no_crash(value: str):
    """removeWhitespace should never crash."""
    result, changed = get_transform("removewhitespace")(value)
    assert isinstance(result, str)
    assert isinstance(changed, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_compresswhitespace_no_crash(value: str):
    """compressWhitespace should never crash."""
    result, changed = get_transform("compresswhitespace")(value)
    assert isinstance(result, str)
    assert isinstance(changed, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_urldecode_no_crash(value: str):
    """urlDecode should never crash."""
    result, changed = get_transform("urldecode")(value)
    assert isinstance(result, str)
    assert isinstance(changed, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_htmlentitydecode_no_crash(value: str):
    """htmlEntityDecode should never crash."""
    result, changed = get_transform("htmlentitydecode")(value)
    assert isinstance(result, str)
    assert isinstance(changed, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_jsdecode_no_crash(value: str):
    """jsDecode should never crash."""
    result, changed = get_transform("jsdecode")(value)
    assert isinstance(result, str)
    assert isinstance(changed, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_base64decode_no_crash(value: str):
    """base64Decode should never crash (may return unchanged on invalid input)."""
    result, changed = get_transform("base64decode")(value)
    assert isinstance(result, str)
    assert isinstance(changed, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_hexdecode_no_crash(value: str):
    """hexDecode should never crash."""
    result, changed = get_transform("hexdecode")(value)
    assert isinstance(result, str)
    assert isinstance(changed, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_md5_no_crash(value: str):
    """md5 should never crash."""
    result, changed = get_transform("md5")(value)
    assert isinstance(result, str)
    assert isinstance(changed, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_sha1_no_crash(value: str):
    """sha1 should never crash."""
    result, changed = get_transform("sha1")(value)
    assert isinstance(result, str)
    assert isinstance(changed, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_sha256_no_crash(value: str):
    """sha256 should never crash."""
    transform = get_transform("sha256")
    if transform:
        result, changed = transform(value)
        assert isinstance(result, str)
        assert isinstance(changed, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_normalisepath_no_crash(value: str):
    """normalisePath should never crash."""
    result, changed = get_transform("normalisepath")(value)
    assert isinstance(result, str)
    assert isinstance(changed, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_cmdline_no_crash(value: str):
    """cmdLine should never crash."""
    result, changed = get_transform("cmdline")(value)
    assert isinstance(result, str)
    assert isinstance(changed, bool)


@given(value=safe_text)
@settings(max_examples=100)
def test_removenulls_no_crash(value: str):
    """removeNulls should never crash."""
    result, changed = get_transform("removenulls")(value)
    assert isinstance(result, str)
    assert isinstance(changed, bool)


# -----------------------------------------------------------------------------
# Idempotency Properties: t(t(x)) == t(x)
# -----------------------------------------------------------------------------


@given(value=safe_text)
@settings(max_examples=100)
def test_lowercase_idempotent(value: str):
    """lowercase(lowercase(x)) == lowercase(x)."""
    transform = get_transform("lowercase")
    first, _ = transform(value)
    second, _ = transform(first)
    assert first == second


@given(value=safe_text)
@settings(max_examples=100)
def test_uppercase_idempotent(value: str):
    """uppercase(uppercase(x)) == uppercase(x)."""
    transform = get_transform("uppercase")
    first, _ = transform(value)
    second, _ = transform(first)
    assert first == second


@given(value=safe_text)
@settings(max_examples=100)
def test_trim_idempotent(value: str):
    """trim(trim(x)) == trim(x)."""
    transform = get_transform("trim")
    first, _ = transform(value)
    second, _ = transform(first)
    assert first == second


@given(value=safe_text)
@settings(max_examples=100)
def test_removewhitespace_idempotent(value: str):
    """removeWhitespace(removeWhitespace(x)) == removeWhitespace(x)."""
    transform = get_transform("removewhitespace")
    first, _ = transform(value)
    second, _ = transform(first)
    assert first == second


@given(value=safe_text)
@settings(max_examples=100)
def test_compresswhitespace_idempotent(value: str):
    """compressWhitespace(compressWhitespace(x)) == compressWhitespace(x)."""
    transform = get_transform("compresswhitespace")
    first, _ = transform(value)
    second, _ = transform(first)
    assert first == second


@given(value=safe_text)
@settings(max_examples=100)
def test_normalisepath_idempotent(value: str):
    """normalisePath(normalisePath(x)) == normalisePath(x)."""
    transform = get_transform("normalisepath")
    first, _ = transform(value)
    second, _ = transform(first)
    assert first == second


@given(value=safe_text)
@settings(max_examples=100)
def test_removenulls_idempotent(value: str):
    """removeNulls(removeNulls(x)) == removeNulls(x)."""
    transform = get_transform("removenulls")
    first, _ = transform(value)
    second, _ = transform(first)
    assert first == second


@given(value=safe_text)
@settings(max_examples=100)
def test_htmlentitydecode_idempotent(value: str):
    """htmlEntityDecode(htmlEntityDecode(x)) == htmlEntityDecode(x).

    After decoding once, there should be no more entities to decode.
    """
    transform = get_transform("htmlentitydecode")
    first, _ = transform(value)
    second, _ = transform(first)
    assert first == second


# -----------------------------------------------------------------------------
# Reversibility Properties: decode(encode(x)) == x
# -----------------------------------------------------------------------------


@given(value=st.binary(max_size=50))
@settings(max_examples=100)
def test_base64_roundtrip(value: bytes):
    """base64Decode(base64Encode(x)) == x for valid binary data."""
    encode = get_transform("base64encode")
    decode = get_transform("base64decode")

    # Encode the binary as latin-1 string for transformation
    text_value = value.decode("latin-1")

    encoded, _ = encode(text_value)
    decoded, _ = decode(encoded)

    # The decoded result should match the original
    assert decoded == text_value


@given(value=st.binary(max_size=50))
@settings(max_examples=100)
def test_hex_roundtrip(value: bytes):
    """hexDecode(hexEncode(x)) == x."""
    encode = get_transform("hexencode")
    decode = get_transform("hexdecode")

    text_value = value.decode("latin-1")

    encoded, _ = encode(text_value)
    decoded, _ = decode(encoded)

    assert decoded == text_value


@given(value=st.text(alphabet=url_chars, max_size=50))
@settings(max_examples=100)
def test_url_roundtrip_simple(value: str):
    """For URL-safe characters, urlDecode(urlEncode(x)) == x."""
    encode = get_transform("urlencode")
    decode = get_transform("urldecode")

    if encode:
        encoded, _ = encode(value)
        decoded, _ = decode(encoded)
        # URL encoding preserves URL-safe characters
        assert decoded == value


# -----------------------------------------------------------------------------
# Length Properties
# -----------------------------------------------------------------------------


@given(value=safe_text)
@settings(max_examples=100)
def test_lowercase_preserves_length(value: str):
    """lowercase preserves string length."""
    result, _ = get_transform("lowercase")(value)
    assert len(result) == len(value)


@given(value=st.text(alphabet=string.ascii_letters + string.digits + string.punctuation, max_size=100))
@settings(max_examples=100)
def test_uppercase_preserves_length_ascii(value: str):
    """uppercase preserves string length for ASCII text.

    Note: Some Unicode characters change length when uppercased (e.g., 'ß' -> 'SS'),
    so this property only holds for ASCII.
    """
    result, _ = get_transform("uppercase")(value)
    assert len(result) == len(value)


@given(value=safe_text)
@settings(max_examples=100)
def test_trim_reduces_or_preserves_length(value: str):
    """trim length is <= original length."""
    result, _ = get_transform("trim")(value)
    assert len(result) <= len(value)


@given(value=safe_text)
@settings(max_examples=100)
def test_removewhitespace_reduces_or_preserves_length(value: str):
    """removeWhitespace length is <= original length."""
    result, _ = get_transform("removewhitespace")(value)
    assert len(result) <= len(value)


@given(value=safe_text)
@settings(max_examples=100)
def test_compresswhitespace_reduces_or_preserves_length(value: str):
    """compressWhitespace length is <= original length."""
    result, _ = get_transform("compresswhitespace")(value)
    assert len(result) <= len(value)


@given(value=safe_text)
@settings(max_examples=100)
def test_length_returns_numeric_string(value: str):
    """length transformation returns a numeric string."""
    result, _ = get_transform("length")(value)
    assert result.isdigit() or result == "0"
    assert int(result) == len(value)


# -----------------------------------------------------------------------------
# Hash Properties
# -----------------------------------------------------------------------------


@given(value=safe_text)
@settings(max_examples=100)
def test_md5_fixed_length(value: str):
    """md5 always returns a 32-character hex string."""
    result, _ = get_transform("md5")(value)
    assert len(result) == 32
    assert all(c in "0123456789abcdef" for c in result)


@given(value=safe_text)
@settings(max_examples=100)
def test_sha1_fixed_length(value: str):
    """sha1 always returns a 40-character hex string."""
    result, _ = get_transform("sha1")(value)
    assert len(result) == 40
    assert all(c in "0123456789abcdef" for c in result)


@given(value=safe_text)
@settings(max_examples=100)
def test_sha256_fixed_length(value: str):
    """sha256 always returns a 64-character hex string."""
    transform = get_transform("sha256")
    if transform:
        result, _ = transform(value)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)


@given(value=safe_text)
@settings(max_examples=50)
def test_md5_deterministic(value: str):
    """md5(x) == md5(x) (determinism)."""
    transform = get_transform("md5")
    result1, _ = transform(value)
    result2, _ = transform(value)
    assert result1 == result2


@given(value=safe_text)
@settings(max_examples=50)
def test_sha1_deterministic(value: str):
    """sha1(x) == sha1(x) (determinism)."""
    transform = get_transform("sha1")
    result1, _ = transform(value)
    result2, _ = transform(value)
    assert result1 == result2


# -----------------------------------------------------------------------------
# Character Preservation Properties
# -----------------------------------------------------------------------------


@given(value=safe_text)
@settings(max_examples=100)
def test_lowercase_only_changes_uppercase(value: str):
    """lowercase only changes uppercase letters."""
    result, _ = get_transform("lowercase")(value)
    for i, (orig, new) in enumerate(zip(value, result)):
        if orig.isupper():
            assert new == orig.lower()
        else:
            assert new == orig


@given(value=st.text(alphabet=string.ascii_letters + string.digits + string.punctuation, max_size=100))
@settings(max_examples=100)
def test_uppercase_only_changes_lowercase_ascii(value: str):
    """uppercase only changes lowercase letters for ASCII text.

    Note: Some Unicode characters change length when uppercased (e.g., 'ß' -> 'SS'),
    so this property only holds for ASCII.
    """
    result, _ = get_transform("uppercase")(value)
    for i, (orig, new) in enumerate(zip(value, result)):
        if orig.islower():
            assert new == orig.upper()
        else:
            assert new == orig


@given(value=safe_text)
@settings(max_examples=100)
def test_removewhitespace_no_whitespace_in_result(value: str):
    """removeWhitespace result contains no whitespace."""
    result, _ = get_transform("removewhitespace")(value)
    assert not any(c.isspace() for c in result)


@given(value=safe_text)
@settings(max_examples=100)
def test_removenulls_no_nulls_in_result(value: str):
    """removeNulls result contains no null characters."""
    result, _ = get_transform("removenulls")(value)
    assert "\x00" not in result


# -----------------------------------------------------------------------------
# None Transform Properties
# -----------------------------------------------------------------------------


@given(value=safe_text)
@settings(max_examples=100)
def test_none_transform_identity(value: str):
    """none transform returns input unchanged."""
    result, changed = get_transform("none")(value)
    assert result == value
    assert changed is False


# -----------------------------------------------------------------------------
# Changed Flag Consistency
# -----------------------------------------------------------------------------


@given(value=safe_text)
@settings(max_examples=100)
def test_lowercase_changed_flag_consistent(value: str):
    """lowercase changed flag is True iff result differs from input."""
    result, changed = get_transform("lowercase")(value)
    assert changed == (result != value)


@given(value=safe_text)
@settings(max_examples=100)
def test_uppercase_changed_flag_consistent(value: str):
    """uppercase changed flag is True iff result differs from input."""
    result, changed = get_transform("uppercase")(value)
    assert changed == (result != value)


@given(value=safe_text)
@settings(max_examples=100)
def test_trim_changed_flag_consistent(value: str):
    """trim changed flag is True iff result differs from input."""
    result, changed = get_transform("trim")(value)
    assert changed == (result != value)


@given(value=safe_text)
@settings(max_examples=100)
def test_removewhitespace_changed_flag_consistent(value: str):
    """removeWhitespace changed flag is True iff result differs from input."""
    result, changed = get_transform("removewhitespace")(value)
    assert changed == (result != value)
