"""Tests for Phase 1 features: new operators, actions, and variables."""

from __future__ import annotations

import pytest

from coraza_poc.primitives.operators import (
    NoMatchOperator,
    RestPathOperator,
    ValidateSchemaOperator,
    ValidateUrlEncodingOperator,
    get_operator,
    OperatorOptions,
)
from coraza_poc.primitives.actions import (
    AuditLogAction,
    NoAuditLogAction,
    RedirectAction,
    RevAction,
    SkipAction,
    ACTIONS,
)
from coraza_poc.primitives.collections import TransactionVariables


class MockTransaction:
    """Mock transaction for testing."""

    def __init__(self):
        self._capturing = False
        self._captures = {}
        self.interruption: dict[str, str | int] | None = None

    def capturing(self) -> bool:
        return self._capturing

    def capture_field(self, index: int, value: str) -> None:
        self._captures[index] = value

    def interrupt(self, rule) -> None:
        self.interruption = {"rule_id": rule.id, "action": "deny"}


class MockRule:
    """Mock rule for testing actions."""

    def __init__(self, rule_id=1):
        self.id = rule_id


def test_nomatch_operator():
    """Test noMatch operator always returns False."""
    op = NoMatchOperator("")
    tx = MockTransaction()

    assert op.evaluate(tx, "anything") is False
    assert op.evaluate(tx, "") is False
    assert op.evaluate(tx, "123") is False


def test_nomatch_operator_factory():
    """Test noMatch operator factory."""
    options = OperatorOptions("")
    op = get_operator("nomatch", options)
    tx = MockTransaction()

    assert isinstance(op, NoMatchOperator)
    assert op.evaluate(tx, "test") is False


def test_validate_url_encoding_operator():
    """Test validateUrlEncoding operator."""
    op = ValidateUrlEncodingOperator("")
    tx = MockTransaction()

    # Valid URL encoding should return False (no error)
    assert op.evaluate(tx, "hello%20world") is False
    assert op.evaluate(tx, "test%2Fpath") is False
    assert op.evaluate(tx, "normal-text") is False

    # Invalid URL encoding should return True (error found)
    assert op.evaluate(tx, "bad%G1encoding") is True
    assert op.evaluate(tx, "incomplete%2") is True
    assert op.evaluate(tx, "bad%") is True


def test_validate_schema_operator():
    """Test validateSchema operator."""
    op = ValidateSchemaOperator("")
    tx = MockTransaction()

    # Valid JSON should return False (no error)
    assert op.evaluate(tx, '{"valid": "json"}') is False
    assert op.evaluate(tx, "[1, 2, 3]") is False

    # Valid XML should return False (no error)
    assert op.evaluate(tx, "<root><child>value</child></root>") is False

    # Invalid JSON/XML should return True (validation failed)
    assert op.evaluate(tx, '{"invalid": json}') is True
    assert op.evaluate(tx, "<invalid><xml>") is True
    assert op.evaluate(tx, "plain text") is True


def test_restpath_operator():
    """Test restpath operator."""
    op = RestPathOperator("/api/users/{id}/posts/{post_id}")
    tx = MockTransaction()

    # Matching paths should return True
    assert op.evaluate(tx, "/api/users/123/posts/456") is True
    assert op.evaluate(tx, "/api/users/abc/posts/xyz") is True

    # Non-matching paths should return False
    assert op.evaluate(tx, "/api/users/123") is False
    assert op.evaluate(tx, "/api/users/123/posts") is False
    assert op.evaluate(tx, "/different/path") is False


def test_restpath_operator_simple():
    """Test restpath operator with simple pattern."""
    op = RestPathOperator("/users/{id}")
    tx = MockTransaction()

    assert op.evaluate(tx, "/users/123") is True
    assert op.evaluate(tx, "/users/abc") is True
    assert op.evaluate(tx, "/users/") is False
    assert op.evaluate(tx, "/users") is False


def test_auditlog_action():
    """Test auditlog action."""
    action = AuditLogAction()
    rule = MockRule(123)
    tx = MockTransaction()

    # Should be non-disruptive
    from coraza_poc.primitives.actions import ActionType

    assert action.action_type() == ActionType.NONDISRUPTIVE

    # Should not interrupt transaction
    action.evaluate(rule, tx)
    assert tx.interruption is None


def test_noauditlog_action():
    """Test noauditlog action."""
    action = NoAuditLogAction()
    rule = MockRule(123)
    tx = MockTransaction()

    # Should be non-disruptive
    from coraza_poc.primitives.actions import ActionType

    assert action.action_type() == ActionType.NONDISRUPTIVE

    # Should not interrupt transaction
    action.evaluate(rule, tx)
    assert tx.interruption is None


def test_redirect_action():
    """Test redirect action."""
    action = RedirectAction()
    rule = MockRule(123)
    tx = MockTransaction()

    # Should require URL
    with pytest.raises(ValueError, match="Redirect action requires a URL"):
        action.init({}, "")

    # Should initialize with URL
    action.init({}, "https://example.com")
    assert action.redirect_url == "https://example.com"

    # Should be disruptive
    from coraza_poc.primitives.actions import ActionType

    assert action.action_type() == ActionType.DISRUPTIVE

    # Should interrupt transaction
    action.evaluate(rule, tx)
    assert tx.interruption is not None
    assert tx.interruption["rule_id"] == 123


def test_skip_action():
    """Test skip action."""
    action = SkipAction()
    rule = MockRule(123)
    tx = MockTransaction()

    # Should require skip count
    with pytest.raises(
        ValueError, match="Skip action requires number of rules to skip"
    ):
        action.init({}, "")

    # Should require valid integer
    with pytest.raises(ValueError, match="Skip count must be an integer"):
        action.init({}, "not_a_number")

    # Should initialize with skip count
    action.init({}, "5")
    assert action.skip_count == 5

    # Should be flow action
    from coraza_poc.primitives.actions import ActionType

    assert action.action_type() == ActionType.FLOW

    # Should not interrupt transaction
    action.evaluate(rule, tx)
    assert tx.interruption is None


def test_rev_action():
    """Test rev action."""
    action = RevAction()
    rule = MockRule(123)
    tx = MockTransaction()

    # Should require revision number
    with pytest.raises(ValueError, match="Rev action requires a revision number"):
        action.init({}, "")

    # Should initialize with revision
    action.init({}, "1.2.3")
    assert action.revision == "1.2.3"

    # Should be metadata action
    from coraza_poc.primitives.actions import ActionType

    assert action.action_type() == ActionType.METADATA

    # Should not interrupt transaction
    action.evaluate(rule, tx)
    assert tx.interruption is None


def test_action_registry():
    """Test that new actions are registered correctly."""
    assert "auditlog" in ACTIONS
    assert "noauditlog" in ACTIONS
    assert "redirect" in ACTIONS
    assert "skip" in ACTIONS
    assert "rev" in ACTIONS


def test_transaction_variables_new_fields():
    """Test that new variables are available."""
    variables = TransactionVariables()

    # Check that new variables exist
    assert hasattr(variables, "server_addr")
    assert hasattr(variables, "server_port")
    assert hasattr(variables, "query_string")
    assert hasattr(variables, "matched_var")
    assert hasattr(variables, "matched_var_name")

    # Check variable names
    assert variables.server_addr.name() == "SERVER_ADDR"
    assert variables.server_port.name() == "SERVER_PORT"
    assert variables.query_string.name() == "QUERY_STRING"
    assert variables.matched_var.name() == "MATCHED_VAR"
    assert variables.matched_var_name.name() == "MATCHED_VAR_NAME"


def test_phase1_crs_sample_rules():
    """Test that Phase 1 features work with CRS-style rules."""
    from coraza_poc.integration import WAF

    # Sample rules using new features
    sample_rules = [
        # Rule using noMatch (should never trigger)
        'SecRule ARGS "@noMatch" "id:1001,phase:2,block,msg:\'This should never match\'"',
        # Rule using validateUrlEncoding
        'SecRule REQUEST_URI "@validateUrlEncoding" "id:1002,phase:1,block,msg:\'Invalid URL encoding\'"',
        # Rule using auditlog action
        'SecRule REQUEST_METHOD "@within GET POST" "id:1003,phase:1,pass,auditlog,msg:\'Valid method\'"',
        # Rule using rev action
        "SecRule ARGS \"@contains script\" \"id:1004,phase:2,block,msg:'Script detected',rev:'1.0'\"",
    ]

    parsed_count = 0
    for rule in sample_rules:
        try:
            config = {"rules": [rule]}
            waf = WAF(config)
            waf.new_transaction()
            parsed_count += 1
            print(f"✓ Parsed: {rule[:60]}...")
        except Exception as e:
            print(f"✗ Failed: {rule[:60]}... - {e}")

    # All new rules should parse successfully
    success_rate = parsed_count / len(sample_rules)
    assert success_rate == 1.0, f"Expected 100% success rate, got {success_rate:.1%}"


def test_restpath_with_crs_style():
    """Test restpath operator with CRS-style rule."""
    from coraza_poc.integration import WAF

    rule = 'SecRule REQUEST_URI "@restpath /api/users/{id}" "id:1005,phase:1,pass,msg:\'REST API access\'"'

    try:
        config = {"rules": [rule]}
        waf = WAF(config)
        tx = waf.new_transaction()
        assert tx is not None
        print("✓ REST path rule parsed successfully")
    except Exception as e:
        pytest.fail(f"REST path rule failed to parse: {e}")
