"""Tests for the kernel module."""

from __future__ import annotations

import pytest

from lewaf.kernel import KernelType, get_kernel, rust_available
from lewaf.kernel.protocol import KernelProtocol
from lewaf.kernel.python_kernel import PythonKernel


class TestKernelFactory:
    """Tests for kernel factory function."""

    def test_get_python_kernel(self) -> None:
        """Test getting Python kernel explicitly."""
        kernel = get_kernel(KernelType.PYTHON)
        assert isinstance(kernel, PythonKernel)

    def test_get_kernel_from_string(self) -> None:
        """Test getting kernel from string."""
        kernel = get_kernel("python")
        assert isinstance(kernel, PythonKernel)

    def test_get_kernel_auto(self) -> None:
        """Test auto-detection of kernel."""
        kernel = get_kernel(KernelType.AUTO)
        # Should always return a valid kernel
        assert isinstance(kernel, KernelProtocol)

    def test_invalid_kernel_type(self) -> None:
        """Test invalid kernel type raises error."""
        with pytest.raises(ValueError, match="Invalid kernel_type"):
            get_kernel("invalid")

    def test_rust_available_returns_bool(self) -> None:
        """Test rust_available returns a boolean."""
        result = rust_available()
        assert isinstance(result, bool)


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
        matched, var_name, value = kernel.evaluate_rule(
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
        matched, var_name, value = kernel.evaluate_rule(
            operator_name="pm",
            operator_arg="select insert update delete",
            transforms=["lowercase"],
            values=[("ARGS:query", "SELECT * FROM users")],
            negated=False,
        )
        assert matched


class TestKernelProtocol:
    """Tests for kernel protocol compliance."""

    def test_python_kernel_implements_protocol(self) -> None:
        """Test PythonKernel implements KernelProtocol."""
        kernel = PythonKernel()
        assert isinstance(kernel, KernelProtocol)
