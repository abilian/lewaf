from typing import Tuple

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
    import re

    removed = re.sub(r"\s", "", value)
    return removed, removed != value
