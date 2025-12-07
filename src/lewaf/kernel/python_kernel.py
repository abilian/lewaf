"""
Pure Python Kernel Implementation.

Wraps the existing LeWAF primitives to implement the KernelProtocol.
This serves as the baseline for performance comparison with Rust.
"""

from __future__ import annotations

import fnmatch
import logging

from lewaf.core import compile_regex
from lewaf.primitives.transformations import TRANSFORMATIONS

__all__ = ["PythonKernel"]


class PythonKernel:
    """
    Pure Python kernel implementation.

    Wraps existing LeWAF code to implement the KernelProtocol interface.
    This is the reference implementation for correctness testing.
    """

    __slots__ = ()

    # =========================================================================
    # Level 1: Primitive Operations
    # =========================================================================

    def regex_match(self, pattern: str, text: str) -> bool:
        """Match a regex pattern against text."""
        regex = compile_regex(pattern)
        return regex.search(text) is not None

    def regex_match_with_captures(
        self, pattern: str, text: str
    ) -> tuple[bool, list[str]]:
        """Match regex and return capture groups (max 9)."""
        regex = compile_regex(pattern)
        match = regex.search(text)
        if match:
            # Max 9 capture groups like ModSecurity
            groups = [g if g is not None else "" for g in match.groups()[:9]]
            return True, groups
        return False, []

    def phrase_match(self, phrases: list[str], text: str) -> bool:
        """
        Check if any phrase exists in text (case-insensitive).

        Note: This is O(p*n) where p=phrases, n=text length.
        Rust implementation uses Aho-Corasick for O(n).
        """
        text_lower = text.lower()
        return any(phrase.lower() in text_lower for phrase in phrases)

    def transform(self, name: str, value: str) -> str:
        """Apply a single transformation."""
        fn = TRANSFORMATIONS.get(name.lower())
        if fn is None:
            return value
        result, _ = fn(value)
        return result

    def transform_chain(self, transforms: list[str], value: str) -> str:
        """Apply a chain of transformations in sequence."""
        result = value
        for t_name in transforms:
            result = self.transform(t_name, result)
        return result

    # =========================================================================
    # Level 2: Operator Evaluation
    # =========================================================================

    def evaluate_rx(
        self, pattern: str, value: str, capture: bool
    ) -> tuple[bool, list[str]]:
        """Evaluate @rx (regex) operator."""
        if capture:
            return self.regex_match_with_captures(pattern, value)
        return self.regex_match(pattern, value), []

    def evaluate_pm(self, phrases: list[str], value: str) -> bool:
        """Evaluate @pm (phrase match) operator."""
        return self.phrase_match(phrases, value)

    def evaluate_contains(self, needle: str, haystack: str) -> bool:
        """Evaluate @contains operator (case-sensitive)."""
        return needle in haystack

    def evaluate_streq(self, expected: str, actual: str) -> bool:
        """Evaluate @streq (string equals) operator."""
        return expected == actual

    def evaluate_eq(self, expected: int, actual: str) -> bool:
        """Evaluate @eq (numeric equals) operator."""
        try:
            return int(actual) == expected
        except (ValueError, TypeError):
            return False

    def evaluate_gt(self, threshold: int, actual: str) -> bool:
        """Evaluate @gt (greater than) operator."""
        try:
            return int(actual) > threshold
        except (ValueError, TypeError):
            return False

    def evaluate_lt(self, threshold: int, actual: str) -> bool:
        """Evaluate @lt (less than) operator."""
        try:
            return int(actual) < threshold
        except (ValueError, TypeError):
            return False

    def evaluate_ge(self, threshold: int, actual: str) -> bool:
        """Evaluate @ge (greater or equal) operator."""
        try:
            return int(actual) >= threshold
        except (ValueError, TypeError):
            return False

    def evaluate_le(self, threshold: int, actual: str) -> bool:
        """Evaluate @le (less or equal) operator."""
        try:
            return int(actual) <= threshold
        except (ValueError, TypeError):
            return False

    def evaluate_beginswith(self, prefix: str, value: str) -> bool:
        """Evaluate @beginsWith operator."""
        return value.startswith(prefix)

    def evaluate_endswith(self, suffix: str, value: str) -> bool:
        """Evaluate @endsWith operator."""
        return value.endswith(suffix)

    def evaluate_within(self, allowed: str, value: str) -> bool:
        """Evaluate @within operator (value must be in allowed list)."""
        allowed_values = allowed.split()
        return value in allowed_values

    def evaluate_strmatch(self, pattern: str, value: str) -> bool:
        """Evaluate @strmatch operator (glob-style pattern matching)."""
        return fnmatch.fnmatch(value, pattern)

    # =========================================================================
    # Level 2.5: Generic Operator Dispatch
    # =========================================================================

    def evaluate_operator(
        self,
        operator_name: str,
        operator_arg: str,
        value: str,
        capture: bool = False,
    ) -> tuple[bool, list[str]]:
        """
        Evaluate any operator by name.

        This dispatches to the appropriate operator method based on name.
        """
        op_name = operator_name.lower()

        # Regex operator (supports captures)
        if op_name == "rx":
            return self.evaluate_rx(operator_arg, value, capture)

        # Phrase match operator
        if op_name == "pm":
            phrases = operator_arg.split()
            return self.evaluate_pm(phrases, value), []

        # String operators
        if op_name == "contains":
            return self.evaluate_contains(operator_arg, value), []
        if op_name == "streq":
            return self.evaluate_streq(operator_arg, value), []
        if op_name == "beginswith":
            return self.evaluate_beginswith(operator_arg, value), []
        if op_name == "endswith":
            return self.evaluate_endswith(operator_arg, value), []
        if op_name == "within":
            return self.evaluate_within(operator_arg, value), []
        if op_name == "strmatch":
            return self.evaluate_strmatch(operator_arg, value), []

        # Numeric operators
        if op_name == "eq":
            try:
                return self.evaluate_eq(int(operator_arg), value), []
            except ValueError:
                return False, []
        if op_name == "gt":
            try:
                return self.evaluate_gt(int(operator_arg), value), []
            except ValueError:
                return False, []
        if op_name == "lt":
            try:
                return self.evaluate_lt(int(operator_arg), value), []
            except ValueError:
                return False, []
        if op_name == "ge":
            try:
                return self.evaluate_ge(int(operator_arg), value), []
            except ValueError:
                return False, []
        if op_name == "le":
            try:
                return self.evaluate_le(int(operator_arg), value), []
            except ValueError:
                return False, []

        # Unconditional operators (always match or never match)
        if op_name in ("unconditional", "unconditionalmatch"):
            return True, []
        if op_name == "nomatch":
            return False, []

        # Unknown operator - fall back to existing operator implementation
        # This allows operators not yet in the kernel to still work
        return self._fallback_evaluate(operator_name, operator_arg, value, capture)

    def _fallback_evaluate(
        self,
        operator_name: str,
        operator_arg: str,
        value: str,
        capture: bool,
    ) -> tuple[bool, list[str]]:
        """
        Fall back to the existing operator implementation for unsupported operators.

        This ensures backwards compatibility while we migrate operators to the kernel.
        """
        # Lazy import to avoid circular dependency
        from lewaf.primitives.operators import (  # noqa: PLC0415
            OperatorOptions,
            get_operator,
        )

        try:
            options = OperatorOptions(arguments=operator_arg)
            op = get_operator(operator_name, options)
            # Create a minimal transaction-like object for evaluation
            matched = op.evaluate(_DummyTransaction(capture), value)  # type: ignore[arg-type]
            return matched, []
        except (ValueError, KeyError, TypeError) as e:
            # Unknown operator or error - no match
            logging.debug("Fallback operator %s failed: %s", operator_name, e)
            return False, []

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
        """
        Evaluate a complete rule against multiple values.

        Implements the full rule evaluation loop:
        1. For each value, apply transformation chain
        2. Evaluate operator on transformed value
        3. Handle negation
        4. Return on first match
        """
        for var_name, value in values:
            # Apply transformations
            transformed = self.transform_chain(transforms, value)

            # Evaluate operator
            matched = self._evaluate_operator(operator_name, operator_arg, transformed)

            # Handle negation
            if negated:
                matched = not matched

            if matched:
                return True, var_name, transformed

        return False, None, None

    def _evaluate_operator(
        self, operator_name: str, operator_arg: str, value: str
    ) -> bool:
        """Dispatch to evaluate_operator (without captures)."""
        matched, _ = self.evaluate_operator(
            operator_name, operator_arg, value, capture=False
        )
        return matched


class _DummyTransaction:
    """Minimal transaction-like object for operator fallback evaluation."""

    def __init__(self, capture: bool = False):
        self._capture = capture
        self._captures: list[str] = []

    def capturing(self) -> bool:
        return self._capture

    def capture_field(self, index: int, value: str) -> None:
        # Pad captures list if needed
        while len(self._captures) < index:
            self._captures.append("")
        if index <= len(self._captures):
            self._captures[index - 1] = value
        else:
            self._captures.append(value)
