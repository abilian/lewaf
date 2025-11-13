from __future__ import annotations

import logging
import re
from functools import lru_cache

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def _translate_perl_regex(pattern: str) -> str:
    """Translate Perl-specific regex syntax to Python-compatible syntax.

    Args:
        pattern: Perl regex pattern

    Returns:
        Python-compatible regex pattern
    """
    # Perl's \z matches end of string only (no trailing newline)
    # Python's $ matches end of string or before final newline
    # For compatibility, we translate \z to \Z (which is closer to Perl's \z)
    pattern = pattern.replace(r"\z", r"\Z")

    # Python requires inline flags (?i) (?m) etc to be at the start
    # CRS often has patterns like ^(?i)pattern which fail in Python
    # We need to move inline flags to the beginning

    # Match inline flags like (?i) (?m) (?s) (?x) or combinations (?im)
    flag_pattern = r"(\(\?[imsxauL]+\))"
    flags_match = re.search(flag_pattern, pattern)

    if flags_match and flags_match.start() > 0:
        # Flags are not at the start, move them
        flags = flags_match.group(1)
        # Remove flags from current position
        pattern_without_flags = (
            pattern[: flags_match.start()] + pattern[flags_match.end() :]
        )
        # Put flags at the beginning
        pattern = flags + pattern_without_flags

    return pattern


@lru_cache(maxsize=128)
def compile_regex(pattern: str) -> re.Pattern:
    """Compile a regex pattern with Perl compatibility translation.

    Args:
        pattern: Regex pattern (may contain Perl-specific syntax)

    Returns:
        Compiled regex pattern object
    """
    logging.debug("Compiling regex: %s", pattern)

    # Translate Perl-specific syntax
    translated = _translate_perl_regex(pattern)

    if translated != pattern:
        logging.debug("Translated regex: %s", translated)

    return re.compile(translated)
