"""Zig kernel wrapper for LeWAF.

This module provides the ZigKernel class that wraps the Zig/PCRE2
implementation via cffi bindings.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .protocol import KernelProtocol

# Add the lewaf-zig python package to the path
# Path: src/lewaf/kernel/zig_kernel.py -> project_root/lewaf-zig/python
_project_root = Path(
    __file__
).parent.parent.parent.parent  # src/lewaf/kernel -> project root
_zig_python_path = _project_root / "lewaf-zig" / "python"
if _zig_python_path.exists():
    sys.path.insert(0, str(_zig_python_path))

# Try to import the Zig kernel
try:
    from lewaf_zig import Kernel as _ZigKernel, is_available as _is_available

    ZIG_AVAILABLE = _is_available()
except ImportError:
    ZIG_AVAILABLE = False
    _ZigKernel = None


def is_available() -> bool:
    """Check if Zig kernel is available."""
    return ZIG_AVAILABLE


class ZigKernel:
    """Zig kernel wrapper implementing KernelProtocol.

    This wraps the Zig/PCRE2 implementation via cffi bindings.
    Falls back to PythonKernel if Zig is not available.
    """

    def __init__(self) -> None:
        if not ZIG_AVAILABLE:
            # Fall back to Python kernel
            from .python_kernel import PythonKernel

            self._impl: KernelProtocol = PythonKernel()
            self._using_fallback = True
        else:
            self._impl = _ZigKernel()
            self._using_fallback = False

    @property
    def using_fallback(self) -> bool:
        """Return True if using Python fallback."""
        return self._using_fallback

    # =========================================================================
    # Level 1: Primitive Operations
    # =========================================================================

    def regex_match(self, pattern: str, text: str) -> bool:
        """Match a regex pattern against text."""
        return self._impl.regex_match(pattern, text)

    def regex_match_with_captures(
        self, pattern: str, text: str
    ) -> tuple[bool, list[str]]:
        """Match regex and return capture groups."""
        return self._impl.regex_match_with_captures(pattern, text)

    def phrase_match(self, phrases: list[str], text: str) -> bool:
        """Check if any phrase matches in text."""
        return self._impl.phrase_match(phrases, text)

    def transform(self, name: str, value: str) -> str:
        """Apply a single transformation."""
        return self._impl.transform(name, value)

    def transform_chain(self, transforms: list[str], value: str) -> str:
        """Apply a chain of transformations."""
        return self._impl.transform_chain(transforms, value)

    # =========================================================================
    # Level 2: Operator Evaluation
    # =========================================================================

    def evaluate_rx(
        self, pattern: str, value: str, capture: bool = False
    ) -> tuple[bool, list[str]]:
        """Evaluate @rx (regex) operator."""
        return self._impl.evaluate_rx(pattern, value, capture)

    def evaluate_pm(self, phrases: list[str], value: str) -> bool:
        """Evaluate @pm (phrase match) operator."""
        return self._impl.evaluate_pm(phrases, value)

    def evaluate_contains(self, needle: str, haystack: str) -> bool:
        """Evaluate @contains operator."""
        return self._impl.evaluate_contains(needle, haystack)

    def evaluate_streq(self, expected: str, actual: str) -> bool:
        """Evaluate @streq operator."""
        return self._impl.evaluate_streq(expected, actual)

    def evaluate_eq(self, expected: int, actual: str) -> bool:
        """Evaluate @eq operator."""
        return self._impl.evaluate_eq(expected, actual)

    def evaluate_gt(self, threshold: int, actual: str) -> bool:
        """Evaluate @gt operator."""
        return self._impl.evaluate_gt(threshold, actual)

    def evaluate_lt(self, threshold: int, actual: str) -> bool:
        """Evaluate @lt operator."""
        return self._impl.evaluate_lt(threshold, actual)

    def evaluate_ge(self, threshold: int, actual: str) -> bool:
        """Evaluate @ge operator."""
        return self._impl.evaluate_ge(threshold, actual)

    def evaluate_le(self, threshold: int, actual: str) -> bool:
        """Evaluate @le operator."""
        return self._impl.evaluate_le(threshold, actual)

    # =========================================================================
    # Level 3: Rule Evaluation
    # =========================================================================

    def evaluate_rule(
        self,
        operator_name: str,
        operator_arg: str,
        transforms: list[str],
        values: list[tuple[str, str]],
        negated: bool = False,
    ) -> tuple[bool, str | None, str | None]:
        """Evaluate a complete rule against multiple values."""
        return self._impl.evaluate_rule(
            operator_name, operator_arg, transforms, values, negated
        )
