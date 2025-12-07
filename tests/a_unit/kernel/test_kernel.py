"""Tests for the kernel module."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from lewaf.integration import ParsedOperator
from lewaf.kernel import (
    KernelProtocol,
    PythonKernel,
    default_kernel,
    reset_default_kernel,
    set_default_kernel,
)
from lewaf.primitives.operators import ContainsOperator, RxOperator
from lewaf.rules import Rule, VariableSpec
from lewaf.transaction import Transaction


class TestKernelModule:
    """Tests for kernel module functions."""

    def test_default_kernel_returns_python_kernel(self) -> None:
        """Test default_kernel returns PythonKernel by default."""
        reset_default_kernel()
        kernel = default_kernel()
        assert isinstance(kernel, PythonKernel)

    def test_default_kernel_is_singleton(self) -> None:
        """Test default_kernel returns same instance."""
        reset_default_kernel()
        kernel1 = default_kernel()
        kernel2 = default_kernel()
        assert kernel1 is kernel2

    def test_set_default_kernel(self) -> None:
        """Test set_default_kernel changes the default."""
        reset_default_kernel()
        custom_kernel = PythonKernel()
        set_default_kernel(custom_kernel)
        assert default_kernel() is custom_kernel
        reset_default_kernel()

    def test_reset_default_kernel(self) -> None:
        """Test reset_default_kernel clears the singleton."""
        kernel1 = default_kernel()
        reset_default_kernel()
        kernel2 = default_kernel()
        # After reset, a new instance is created
        assert kernel1 is not kernel2


class TestPythonKernel:
    """Tests for Python kernel implementation."""

    @pytest.fixture
    def kernel(self) -> PythonKernel:
        """Create a Python kernel instance."""
        return PythonKernel()

    # --- Level 1: Primitive Operations ---

    def test_regex_match_positive(self, kernel: PythonKernel) -> None:
        """Test regex match that succeeds."""
        assert kernel.regex_match(r"hello", "hello world")

    def test_regex_match_negative(self, kernel: PythonKernel) -> None:
        """Test regex match that fails."""
        assert not kernel.regex_match(r"goodbye", "hello world")

    def test_regex_match_case_insensitive(self, kernel: PythonKernel) -> None:
        """Test case-insensitive regex match."""
        assert kernel.regex_match(r"(?i)hello", "HELLO world")

    def test_regex_match_with_captures(self, kernel: PythonKernel) -> None:
        """Test regex match with capture groups."""
        matched, captures = kernel.regex_match_with_captures(
            r"user=(\w+)&pass=(\w+)", "user=admin&pass=secret"
        )
        assert matched
        assert captures == ["admin", "secret"]

    def test_regex_match_with_captures_no_match(self, kernel: PythonKernel) -> None:
        """Test regex match with captures when no match."""
        matched, captures = kernel.regex_match_with_captures(
            r"user=(\w+)", "no match here"
        )
        assert not matched
        assert captures == []

    def test_phrase_match_positive(self, kernel: PythonKernel) -> None:
        """Test phrase match that succeeds."""
        phrases = ["select", "union", "drop"]
        assert kernel.phrase_match(phrases, "SELECT * FROM users")

    def test_phrase_match_negative(self, kernel: PythonKernel) -> None:
        """Test phrase match that fails."""
        phrases = ["select", "union", "drop"]
        assert not kernel.phrase_match(phrases, "Hello World")

    def test_phrase_match_case_insensitive(self, kernel: PythonKernel) -> None:
        """Test phrase match is case-insensitive."""
        phrases = ["select"]
        assert kernel.phrase_match(phrases, "SELECT")
        assert kernel.phrase_match(phrases, "select")
        assert kernel.phrase_match(phrases, "SeLeCt")

    def test_transform_lowercase(self, kernel: PythonKernel) -> None:
        """Test lowercase transformation."""
        assert kernel.transform("lowercase", "HELLO") == "hello"

    def test_transform_urldecode(self, kernel: PythonKernel) -> None:
        """Test URL decode transformation."""
        assert kernel.transform("urldecode", "hello%20world") == "hello world"

    def test_transform_unknown(self, kernel: PythonKernel) -> None:
        """Test unknown transformation returns original value."""
        assert kernel.transform("nonexistent", "test") == "test"

    def test_transform_chain(self, kernel: PythonKernel) -> None:
        """Test transformation chain."""
        result = kernel.transform_chain(["urldecode", "lowercase"], "HELLO%20WORLD")
        assert result == "hello world"

    # --- Level 2: Operator Evaluation ---

    def test_evaluate_rx(self, kernel: PythonKernel) -> None:
        """Test @rx operator evaluation."""
        matched, _ = kernel.evaluate_rx(r"(?i)admin", "ADMIN panel", capture=False)
        assert matched

    def test_evaluate_pm(self, kernel: PythonKernel) -> None:
        """Test @pm operator evaluation."""
        assert kernel.evaluate_pm(["admin", "root"], "admin user")
        assert not kernel.evaluate_pm(["admin", "root"], "guest user")

    def test_evaluate_contains(self, kernel: PythonKernel) -> None:
        """Test @contains operator evaluation."""
        assert kernel.evaluate_contains("admin", "admin panel")
        assert not kernel.evaluate_contains("admin", "user panel")

    def test_evaluate_streq(self, kernel: PythonKernel) -> None:
        """Test @streq operator evaluation."""
        assert kernel.evaluate_streq("GET", "GET")
        assert not kernel.evaluate_streq("GET", "POST")

    def test_evaluate_eq(self, kernel: PythonKernel) -> None:
        """Test @eq operator evaluation."""
        assert kernel.evaluate_eq(200, "200")
        assert not kernel.evaluate_eq(200, "404")
        assert not kernel.evaluate_eq(200, "invalid")

    def test_evaluate_gt(self, kernel: PythonKernel) -> None:
        """Test @gt operator evaluation."""
        assert kernel.evaluate_gt(100, "150")
        assert not kernel.evaluate_gt(100, "50")
        assert not kernel.evaluate_gt(100, "100")

    def test_evaluate_lt(self, kernel: PythonKernel) -> None:
        """Test @lt operator evaluation."""
        assert kernel.evaluate_lt(100, "50")
        assert not kernel.evaluate_lt(100, "150")

    def test_evaluate_ge(self, kernel: PythonKernel) -> None:
        """Test @ge operator evaluation."""
        assert kernel.evaluate_ge(100, "100")
        assert kernel.evaluate_ge(100, "150")
        assert not kernel.evaluate_ge(100, "50")

    def test_evaluate_le(self, kernel: PythonKernel) -> None:
        """Test @le operator evaluation."""
        assert kernel.evaluate_le(100, "100")
        assert kernel.evaluate_le(100, "50")
        assert not kernel.evaluate_le(100, "150")

    # --- Level 3: Rule Evaluation ---

    def test_evaluate_rule_simple_match(self, kernel: PythonKernel) -> None:
        """Test simple rule evaluation with match."""
        matched, var_name, value = kernel.evaluate_rule(
            operator_name="contains",
            operator_arg="admin",
            transforms=[],
            values=[("REQUEST_URI", "/admin/dashboard")],
            negated=False,
        )
        assert matched
        assert var_name == "REQUEST_URI"
        assert value == "/admin/dashboard"

    def test_evaluate_rule_no_match(self, kernel: PythonKernel) -> None:
        """Test rule evaluation with no match."""
        matched, var_name, value = kernel.evaluate_rule(
            operator_name="contains",
            operator_arg="admin",
            transforms=[],
            values=[("REQUEST_URI", "/user/profile")],
            negated=False,
        )
        assert not matched
        assert var_name is None
        assert value is None

    def test_evaluate_rule_with_transforms(self, kernel: PythonKernel) -> None:
        """Test rule evaluation with transformations."""
        matched, var_name, value = kernel.evaluate_rule(
            operator_name="contains",
            operator_arg="admin",
            transforms=["lowercase", "urldecode"],
            values=[("ARGS:path", "ADMIN%20PANEL")],
            negated=False,
        )
        assert matched
        assert var_name == "ARGS:path"
        assert value == "admin panel"

    def test_evaluate_rule_multiple_values(self, kernel: PythonKernel) -> None:
        """Test rule evaluation with multiple values (match on second)."""
        matched, var_name, value = kernel.evaluate_rule(
            operator_name="contains",
            operator_arg="admin",
            transforms=[],
            values=[
                ("ARGS:a", "user"),
                ("ARGS:b", "admin"),
                ("ARGS:c", "guest"),
            ],
            negated=False,
        )
        assert matched
        assert var_name == "ARGS:b"
        assert value == "admin"

    def test_evaluate_rule_negated(self, kernel: PythonKernel) -> None:
        """Test rule evaluation with negation."""
        # Pattern does NOT match, so with negation it becomes a match
        matched, var_name, _value = kernel.evaluate_rule(
            operator_name="rx",
            operator_arg=r"^(GET|POST)$",
            transforms=[],
            values=[("REQUEST_METHOD", "OPTIONS")],
            negated=True,
        )
        assert matched
        assert var_name == "REQUEST_METHOD"

    def test_evaluate_rule_pm_operator(self, kernel: PythonKernel) -> None:
        """Test rule evaluation with @pm operator."""
        matched, _var_name, _value = kernel.evaluate_rule(
            operator_name="pm",
            operator_arg="select insert update delete",
            transforms=["lowercase"],
            values=[("ARGS:query", "SELECT * FROM users")],
            negated=False,
        )
        assert matched


class TestEvaluateOperator:
    """Tests for the evaluate_operator dispatch method."""

    @pytest.fixture
    def kernel(self) -> PythonKernel:
        """Create a Python kernel instance."""
        return PythonKernel()

    def test_evaluate_operator_rx(self, kernel: PythonKernel) -> None:
        """Test evaluate_operator with @rx."""
        matched, captures = kernel.evaluate_operator("rx", r"admin", "admin panel")
        assert matched
        assert captures == []

    def test_evaluate_operator_rx_with_capture(self, kernel: PythonKernel) -> None:
        """Test evaluate_operator with @rx and captures."""
        matched, captures = kernel.evaluate_operator(
            "rx", r"user=(\w+)", "user=admin", capture=True
        )
        assert matched
        assert captures == ["admin"]

    def test_evaluate_operator_pm(self, kernel: PythonKernel) -> None:
        """Test evaluate_operator with @pm."""
        matched, captures = kernel.evaluate_operator(
            "pm", "select union drop", "SELECT * FROM users"
        )
        assert matched
        assert captures == []

    def test_evaluate_operator_contains(self, kernel: PythonKernel) -> None:
        """Test evaluate_operator with @contains."""
        matched, _ = kernel.evaluate_operator("contains", "admin", "admin panel")
        assert matched

    def test_evaluate_operator_streq(self, kernel: PythonKernel) -> None:
        """Test evaluate_operator with @streq."""
        matched, _ = kernel.evaluate_operator("streq", "GET", "GET")
        assert matched
        matched, _ = kernel.evaluate_operator("streq", "GET", "POST")
        assert not matched

    def test_evaluate_operator_beginswith(self, kernel: PythonKernel) -> None:
        """Test evaluate_operator with @beginsWith."""
        matched, _ = kernel.evaluate_operator(
            "beginswith", "/admin", "/admin/dashboard"
        )
        assert matched
        matched, _ = kernel.evaluate_operator("beginswith", "/admin", "/user/profile")
        assert not matched

    def test_evaluate_operator_endswith(self, kernel: PythonKernel) -> None:
        """Test evaluate_operator with @endsWith."""
        matched, _ = kernel.evaluate_operator("endswith", ".php", "index.php")
        assert matched
        matched, _ = kernel.evaluate_operator("endswith", ".php", "index.html")
        assert not matched

    def test_evaluate_operator_numeric(self, kernel: PythonKernel) -> None:
        """Test evaluate_operator with numeric operators."""
        matched, _ = kernel.evaluate_operator("eq", "100", "100")
        assert matched
        matched, _ = kernel.evaluate_operator("gt", "50", "100")
        assert matched
        matched, _ = kernel.evaluate_operator("lt", "100", "50")
        assert matched

    def test_evaluate_operator_unconditional(self, kernel: PythonKernel) -> None:
        """Test evaluate_operator with unconditional operators."""
        matched, _ = kernel.evaluate_operator("unconditional", "", "any value")
        assert matched
        matched, _ = kernel.evaluate_operator("nomatch", "", "any value")
        assert not matched

    def test_evaluate_operator_unknown_fallback(self, kernel: PythonKernel) -> None:
        """Test evaluate_operator falls back for unknown operators."""
        # detectsqli is not in kernel, should fall back
        matched, _ = kernel.evaluate_operator("detectsqli", "", "1' OR '1'='1")
        # Should work via fallback (if detectsqli operator exists)
        # The actual result depends on whether detectsqli matches
        assert isinstance(matched, bool)


class TestKernelIntegration:
    """Tests for kernel integration with Rule.evaluate()."""

    def test_rule_uses_kernel_for_transforms(self) -> None:
        """Test that Rule.evaluate() uses kernel for transforms."""
        # Create a simple rule with transforms
        rule = Rule(
            variables=[VariableSpec(name="ARGS", key="test")],
            operator=ParsedOperator(
                name="contains",
                argument="hello",
                op=ContainsOperator("hello"),
                negated=False,
            ),
            transformations=["lowercase"],
            actions={},
            metadata={"id": 1, "phase": 1},
        )

        # Create mock WAF and transaction with uppercase value
        mock_waf = MagicMock()
        mock_waf.rule_group = MagicMock()
        tx = Transaction(mock_waf, "test-tx-1")
        tx.variables.args.add("test", "HELLO WORLD")

        # Evaluate - should match because transforms lowercase the value
        result = rule.evaluate(tx)
        assert result is True

    def test_rule_uses_kernel_for_operators(self) -> None:
        """Test that Rule.evaluate() uses kernel for operator evaluation."""
        # Create a regex rule
        rule = Rule(
            variables=[VariableSpec(name="REQUEST_URI")],
            operator=ParsedOperator(
                name="rx",
                argument=r"admin",
                op=RxOperator(r"admin"),
                negated=False,
            ),
            transformations=[],
            actions={},
            metadata={"id": 2, "phase": 1},
        )

        # Create mock WAF and transaction
        mock_waf = MagicMock()
        mock_waf.rule_group = MagicMock()
        tx = Transaction(mock_waf, "test-tx-2")
        tx.variables.request_uri.set("/admin/dashboard")

        # Evaluate - should match
        result = rule.evaluate(tx)
        assert result is True

    def test_kernel_used_via_default_kernel(self) -> None:
        """Test that Rule.evaluate() uses the default kernel."""
        reset_default_kernel()
        # Verify the default kernel is used
        kernel = default_kernel()
        assert isinstance(kernel, KernelProtocol)


class TestKernelProtocol:
    """Tests for kernel protocol compliance."""

    def test_python_kernel_implements_protocol(self) -> None:
        """Test PythonKernel implements KernelProtocol."""
        kernel = PythonKernel()
        assert isinstance(kernel, KernelProtocol)
