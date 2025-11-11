"""Unit tests for admin path blocking with @streq operator and lowercase transformation.

This module tests the operator and transformation logic in isolation,
ensuring that @streq correctly matches paths and t:lowercase normalizes case.
"""

from __future__ import annotations

from lewaf.primitives.operators import OperatorOptions, get_operator
from lewaf.primitives.transformations import TRANSFORMATIONS


def test_streq_operator_exact_match():
    """Test @streq operator matches exact string."""
    options = OperatorOptions("/admin")
    operator = get_operator("streq", options)

    tx = None  # Not needed for streq operator

    # Exact match should succeed
    assert operator.evaluate(tx, "/admin") is True

    # Non-matches should fail
    assert operator.evaluate(tx, "/user") is False
    assert operator.evaluate(tx, "/admin/users") is False
    # Case sensitive without transformation
    assert operator.evaluate(tx, "/ADMIN") is False


def test_lowercase_transformation():
    """Test lowercase transformation normalizes case."""
    lowercase_fn = TRANSFORMATIONS["lowercase"]

    # Test various case variations (transformation returns (value, changed) tuple)
    result, changed = lowercase_fn("/ADMIN")
    assert result == "/admin"
    assert changed is True

    result, changed = lowercase_fn("/Admin")
    assert result == "/admin"
    assert changed is True

    result, changed = lowercase_fn("/aDmIn")
    assert result == "/admin"
    assert changed is True

    result, changed = lowercase_fn("/admin")
    assert result == "/admin"
    assert changed is False  # No change

    result, changed = lowercase_fn("/USER")
    assert result == "/user"
    assert changed is True


def test_streq_with_lowercase_transformation():
    """Test @streq operator with lowercase transformation applied.

    This simulates the rule:
    SecRule REQUEST_URI "@streq /admin" "id:101,phase:1,t:lowercase,deny"
    """
    # Setup operator
    options = OperatorOptions("/admin")
    operator = get_operator("streq", options)

    # Setup transformation
    lowercase_fn = TRANSFORMATIONS["lowercase"]

    tx = None

    # Test various URI variations with transformation applied
    test_cases = [
        ("/admin", True, "Lowercase /admin should match"),
        ("/ADMIN", True, "Uppercase /ADMIN should match after transformation"),
        ("/Admin", True, "Mixed case /Admin should match after transformation"),
        ("/aDmIn", True, "Mixed case /aDmIn should match after transformation"),
        ("/user", False, "Different path /user should not match"),
        ("/administrator", False, "Similar path /administrator should not match"),
        ("/admin/users", False, "Sub-path /admin/users should not match"),
        ("/api/admin", False, "Path containing /admin should not match"),
    ]

    for uri, expected, description in test_cases:
        # Apply transformation first, then evaluate
        transformed_uri, _ = lowercase_fn(uri)
        result = operator.evaluate(tx, transformed_uri)
        assert result == expected, (
            f"Failed: {description} (URI: {uri}, transformed: {transformed_uri})"
        )


def test_streq_operator_case_sensitivity_without_transformation():
    """Test that @streq is case-sensitive without transformation."""
    options = OperatorOptions("/admin")
    operator = get_operator("streq", options)

    tx = None

    # Without transformation, case matters
    assert operator.evaluate(tx, "/admin") is True
    assert operator.evaluate(tx, "/ADMIN") is False
    assert operator.evaluate(tx, "/Admin") is False


def test_transformation_chain_with_streq():
    """Test multiple transformations can be applied before operator evaluation."""
    # This tests the transformation pipeline
    options = OperatorOptions("/admin")
    operator = get_operator("streq", options)

    # Get transformations
    lowercase_fn = TRANSFORMATIONS["lowercase"]
    trim_fn = TRANSFORMATIONS["trim"]  # Remove leading/trailing whitespace

    tx = None

    # Apply transformation chain
    uri = "  /ADMIN  "  # Whitespace + uppercase
    transformed, _ = trim_fn(uri)  # First trim
    transformed, _ = lowercase_fn(transformed)  # Then lowercase

    assert transformed == "/admin"
    assert operator.evaluate(tx, transformed) is True


def test_admin_path_blocking_edge_cases():
    """Test edge cases for admin path blocking."""
    options = OperatorOptions("/admin")
    operator = get_operator("streq", options)
    lowercase_fn = TRANSFORMATIONS["lowercase"]

    tx = None

    edge_cases = [
        ("", False, "Empty string should not match"),
        ("/", False, "Root path should not match"),
        ("/admin/", False, "Path with trailing slash should not match"),
        ("admin", False, "Path without leading slash should not match"),
        ("/ADMIN/", False, "Uppercase with trailing slash should not match"),
        ("//admin", False, "Double slash should not match"),
        (
            "/admin/../admin",
            False,
            "Path traversal should not match (as literal string)",
        ),
    ]

    for uri, expected, description in edge_cases:
        transformed, _ = lowercase_fn(uri)
        result = operator.evaluate(tx, transformed)
        assert result == expected, f"Failed: {description} (URI: {uri})"


def test_multiple_blocked_paths():
    """Test that multiple admin paths can be blocked with separate rules."""
    # Simulate multiple rules blocking different paths
    blocked_paths = ["/admin", "/administrator", "/admin-panel"]

    lowercase_fn = TRANSFORMATIONS["lowercase"]
    tx = None

    for path in blocked_paths:
        options = OperatorOptions(path)
        operator = get_operator("streq", options)

        # Test exact match (case insensitive)
        transformed_path, _ = lowercase_fn(path)
        assert operator.evaluate(tx, transformed_path) is True

        transformed_upper, _ = lowercase_fn(path.upper())
        assert operator.evaluate(tx, transformed_upper) is True

        # Test non-match
        transformed_user, _ = lowercase_fn("/user")
        assert operator.evaluate(tx, transformed_user) is False
