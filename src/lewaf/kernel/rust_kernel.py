"""
Rust Kernel Implementation (Stub).

This module wraps the lewaf_core Rust library via PyO3 bindings.
Currently falls back to PythonKernel until Rust implementation is available.
"""

# ruff: noqa: PLC0415
# Late imports are intentional to handle optional lewaf_core dependency.

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lewaf.kernel.protocol import KernelProtocol

__all__ = ["RustKernel"]


class RustKernel:
    """
    Rust kernel implementation via PyO3 bindings.

    Falls back to PythonKernel if lewaf_core is not installed.
    This allows development and testing before Rust implementation.
    """

    __slots__ = ("_inner", "_is_rust")

    def __init__(self) -> None:
        """Initialize Rust kernel, falling back to Python if unavailable."""
        try:
            import lewaf_core

            self._inner: KernelProtocol = lewaf_core.Kernel()
            self._is_rust = True
        except ImportError:
            # Fallback for development: use Python kernel
            from lewaf.kernel.python_kernel import PythonKernel

            self._inner = PythonKernel()
            self._is_rust = False

    @property
    def is_native_rust(self) -> bool:
        """Check if this instance is using the native Rust implementation."""
        return self._is_rust

    # =========================================================================
    # Level 1: Primitive Operations
    # =========================================================================

    def regex_match(self, pattern: str, text: str) -> bool:
        """Match a regex pattern against text."""
        return self._inner.regex_match(pattern, text)

    def regex_match_with_captures(
        self, pattern: str, text: str
    ) -> tuple[bool, list[str]]:
        """Match regex and return capture groups (max 9)."""
        return self._inner.regex_match_with_captures(pattern, text)

    def phrase_match(self, phrases: list[str], text: str) -> bool:
        """Check if any phrase exists in text (case-insensitive)."""
        return self._inner.phrase_match(phrases, text)

    def transform(self, name: str, value: str) -> str:
        """Apply a single transformation."""
        return self._inner.transform(name, value)

    def transform_chain(self, transforms: list[str], value: str) -> str:
        """Apply a chain of transformations in sequence."""
        return self._inner.transform_chain(transforms, value)

    # =========================================================================
    # Level 2: Operator Evaluation
    # =========================================================================

    def evaluate_rx(
        self, pattern: str, value: str, capture: bool
    ) -> tuple[bool, list[str]]:
        """Evaluate @rx (regex) operator."""
        return self._inner.evaluate_rx(pattern, value, capture)

    def evaluate_pm(self, phrases: list[str], value: str) -> bool:
        """Evaluate @pm (phrase match) operator."""
        return self._inner.evaluate_pm(phrases, value)

    def evaluate_contains(self, needle: str, haystack: str) -> bool:
        """Evaluate @contains operator."""
        return self._inner.evaluate_contains(needle, haystack)

    def evaluate_streq(self, expected: str, actual: str) -> bool:
        """Evaluate @streq (string equals) operator."""
        return self._inner.evaluate_streq(expected, actual)

    def evaluate_eq(self, expected: int, actual: str) -> bool:
        """Evaluate @eq (numeric equals) operator."""
        return self._inner.evaluate_eq(expected, actual)

    def evaluate_gt(self, threshold: int, actual: str) -> bool:
        """Evaluate @gt (greater than) operator."""
        return self._inner.evaluate_gt(threshold, actual)

    def evaluate_lt(self, threshold: int, actual: str) -> bool:
        """Evaluate @lt (less than) operator."""
        return self._inner.evaluate_lt(threshold, actual)

    def evaluate_ge(self, threshold: int, actual: str) -> bool:
        """Evaluate @ge (greater or equal) operator."""
        return self._inner.evaluate_ge(threshold, actual)

    def evaluate_le(self, threshold: int, actual: str) -> bool:
        """Evaluate @le (less or equal) operator."""
        return self._inner.evaluate_le(threshold, actual)

    # =========================================================================
    # Level 3: Rule Evaluation
    # =========================================================================

    def evaluate_rule(
        self,
        operator_name: str,
        operator_arg: str,
        transforms: list[str],
        values: list[tuple[str, str]],
        negated: bool,
    ) -> tuple[bool, str | None, str | None]:
        """Evaluate a complete rule against multiple values."""
        return self._inner.evaluate_rule(
            operator_name, operator_arg, transforms, values, negated
        )
