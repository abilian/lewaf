"""
Kernel Protocol Definition.

Defines the interface that all kernel implementations must satisfy.
This enables runtime switching between Python and Rust kernels.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

__all__ = ["KernelProtocol"]


@runtime_checkable
class KernelProtocol(Protocol):
    """
    Protocol defining the pluggable kernel interface.

    All kernel implementations (Python, Rust) must implement these methods.
    The interface is organized in three levels:

    Level 1 - Primitive Operations:
        Low-level operations that form the building blocks.

    Level 2 - Operator Evaluation:
        ModSecurity-compatible operator implementations.

    Level 3 - Rule Evaluation:
        Complete rule evaluation with transforms and multiple values.
    """

    # =========================================================================
    # Level 1: Primitive Operations
    # =========================================================================

    def regex_match(self, pattern: str, text: str) -> bool:
        """
        Match a regex pattern against text.

        Args:
            pattern: Regex pattern (may contain Perl-specific syntax).
            text: Text to search.

        Returns:
            True if pattern matches anywhere in text.
        """
        ...

    def regex_match_with_captures(
        self, pattern: str, text: str
    ) -> tuple[bool, list[str]]:
        """
        Match regex and return capture groups.

        Args:
            pattern: Regex pattern with capture groups.
            text: Text to search.

        Returns:
            Tuple of (matched: bool, captures: list[str]).
            Captures limited to first 9 groups (ModSecurity compatibility).
            Empty strings for non-matching optional groups.
        """
        ...

    def phrase_match(self, phrases: list[str], text: str) -> bool:
        """
        Check if any phrase exists in text (case-insensitive).

        This is the @pm operator - phrase match.
        Python uses linear scan, Rust can use Aho-Corasick for O(n).

        Args:
            phrases: List of phrases to search for.
            text: Text to search in.

        Returns:
            True if any phrase found in text.
        """
        ...

    def transform(self, name: str, value: str) -> str:
        """
        Apply a single transformation to a value.

        Args:
            name: Transformation name (e.g., "lowercase", "urldecode").
            value: Value to transform.

        Returns:
            Transformed value. Returns original if transform unknown.
        """
        ...

    def transform_chain(self, transforms: list[str], value: str) -> str:
        """
        Apply a chain of transformations in sequence.

        Args:
            transforms: List of transformation names.
            value: Initial value.

        Returns:
            Value after all transformations applied.
        """
        ...

    # =========================================================================
    # Level 2: Operator Evaluation
    # =========================================================================

    def evaluate_rx(
        self, pattern: str, value: str, capture: bool
    ) -> tuple[bool, list[str]]:
        """
        Evaluate @rx (regex) operator.

        Args:
            pattern: Regex pattern.
            value: Value to match against.
            capture: Whether to capture groups.

        Returns:
            Tuple of (matched: bool, captures: list[str]).
            Captures empty if capture=False or no match.
        """
        ...

    def evaluate_pm(self, phrases: list[str], value: str) -> bool:
        """
        Evaluate @pm (phrase match) operator.

        Case-insensitive substring matching against multiple phrases.

        Args:
            phrases: List of phrases to match.
            value: Value to search in.

        Returns:
            True if any phrase found.
        """
        ...

    def evaluate_contains(self, needle: str, haystack: str) -> bool:
        """
        Evaluate @contains operator.

        Case-sensitive substring check.

        Args:
            needle: String to search for.
            haystack: String to search in.

        Returns:
            True if needle found in haystack.
        """
        ...

    def evaluate_streq(self, expected: str, actual: str) -> bool:
        """
        Evaluate @streq (string equals) operator.

        Case-sensitive string equality.

        Args:
            expected: Expected string.
            actual: Actual string to compare.

        Returns:
            True if strings are equal.
        """
        ...

    def evaluate_eq(self, expected: int, actual: str) -> bool:
        """
        Evaluate @eq (numeric equals) operator.

        Args:
            expected: Expected numeric value.
            actual: String to parse and compare.

        Returns:
            True if actual parses to expected value.
        """
        ...

    def evaluate_gt(self, threshold: int, actual: str) -> bool:
        """
        Evaluate @gt (greater than) operator.

        Args:
            threshold: Threshold value.
            actual: String to parse and compare.

        Returns:
            True if actual > threshold.
        """
        ...

    def evaluate_lt(self, threshold: int, actual: str) -> bool:
        """
        Evaluate @lt (less than) operator.

        Args:
            threshold: Threshold value.
            actual: String to parse and compare.

        Returns:
            True if actual < threshold.
        """
        ...

    def evaluate_ge(self, threshold: int, actual: str) -> bool:
        """
        Evaluate @ge (greater or equal) operator.

        Args:
            threshold: Threshold value.
            actual: String to parse and compare.

        Returns:
            True if actual >= threshold.
        """
        ...

    def evaluate_le(self, threshold: int, actual: str) -> bool:
        """
        Evaluate @le (less or equal) operator.

        Args:
            threshold: Threshold value.
            actual: String to parse and compare.

        Returns:
            True if actual <= threshold.
        """
        ...

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

        This is the highest-level operation, combining:
        1. Transformation chain on each value
        2. Operator evaluation on transformed value
        3. Negation handling
        4. Early exit on first match

        Args:
            operator_name: Operator name (rx, pm, contains, streq, eq, etc.).
            operator_arg: Operator argument (pattern, phrases, value).
            transforms: List of transformation names to apply.
            values: List of (variable_name, value) tuples to test.
            negated: Whether to negate the match result.

        Returns:
            Tuple of (matched, matched_var_name, matched_value).
            If no match, returns (False, None, None).
        """
        ...
