"""Unit tests for Phase 1 and 2 actions (redirect, skip, drop, setenv, etc.)."""

import os

from lewaf.primitives.actions import (
    ACTIONS,
    ActionType,
    AuditLogAction,
    DropAction,
    ExecAction,
    ExpireVarAction,
    InitColAction,
    NoAuditLogAction,
    RedirectAction,
    RevAction,
    SetEnvAction,
    SkipAction,
)


def test_phase1_actions_registered():
    """Test that Phase 1 actions are registered."""
    assert "redirect" in ACTIONS
    assert "skip" in ACTIONS
    assert "rev" in ACTIONS
    assert "auditlog" in ACTIONS
    assert "noauditlog" in ACTIONS


def test_phase2_actions_registered():
    """Test that Phase 2 actions are registered."""
    assert "drop" in ACTIONS
    assert "exec" in ACTIONS
    assert "setenv" in ACTIONS
    assert "expirevar" in ACTIONS
    assert "initcol" in ACTIONS


def test_redirect_action():
    """Test redirect action functionality."""
    action = RedirectAction()

    assert action.action_type() == ActionType.DISRUPTIVE

    # Test initialization
    action.init({}, "https://example.com/blocked")
    assert action.redirect_url == "https://example.com/blocked"

    # Test with empty URL should raise error
    try:
        action.init({}, "")
        assert False, "Should raise ValueError for empty URL"
    except ValueError:
        pass

    # Test evaluation
    class MockRule:
        def __init__(self):
            self.id = 123

    class MockTransaction:
        def __init__(self):
            self.interruption = None

        def interrupt(self, rule):
            self.interruption = {"rule_id": rule.id, "action": "redirect"}

    rule = MockRule()
    tx = MockTransaction()

    action.evaluate(rule, tx)
    assert tx.interruption is not None


def test_skip_action():
    """Test skip action functionality."""
    action = SkipAction()

    assert action.action_type() == ActionType.FLOW

    # Test initialization
    action.init({}, "5")
    assert action.skip_count == 5

    # Test with invalid number
    try:
        action.init({}, "not_a_number")
        assert False, "Should raise ValueError for invalid number"
    except ValueError:
        pass


def test_rev_action():
    """Test revision action functionality."""
    action = RevAction()

    assert action.action_type() == ActionType.METADATA

    # Test initialization
    action.init({}, "1.2.3")
    assert action.revision == "1.2.3"

    # Test with empty revision
    try:
        action.init({}, "")
        assert False, "Should raise ValueError for empty revision"
    except ValueError:
        pass


def test_auditlog_action():
    """Test audit log action functionality."""
    action = AuditLogAction()

    assert action.action_type() == ActionType.NONDISRUPTIVE

    class MockRule:
        def __init__(self):
            self.id = 123

    class MockTransaction:
        pass

    rule = MockRule()
    tx = MockTransaction()

    # Should not raise exception
    action.evaluate(rule, tx)


def test_noauditlog_action():
    """Test no audit log action functionality."""
    action = NoAuditLogAction()

    assert action.action_type() == ActionType.NONDISRUPTIVE

    class MockRule:
        def __init__(self):
            self.id = 123

    class MockTransaction:
        pass

    rule = MockRule()
    tx = MockTransaction()

    # Should not raise exception
    action.evaluate(rule, tx)


def test_drop_action():
    """Test drop action functionality."""
    action = DropAction()

    assert action.action_type() == ActionType.DISRUPTIVE

    class MockRule:
        def __init__(self):
            self.id = 123

    class MockTransaction:
        def __init__(self):
            self.interruption = None

        def interrupt(self, rule):
            self.interruption = {"rule_id": rule.id, "action": "deny"}

    rule = MockRule()
    tx = MockTransaction()

    action.evaluate(rule, tx)
    assert tx.interruption is not None
    assert tx.interruption["rule_id"] == 123


def test_exec_action():
    """Test exec action functionality (security disabled)."""
    action = ExecAction()

    assert action.action_type() == ActionType.NONDISRUPTIVE

    # Test initialization
    action.init({}, "echo test")
    assert action.command == "echo test"

    # Test with empty command should raise error
    try:
        action.init({}, "")
        assert False, "Should raise ValueError for empty command"
    except ValueError:
        pass

    # Test evaluation (should not execute for security)
    class MockRule:
        def __init__(self):
            self.id = 123

    class MockTransaction:
        def __init__(self):
            self.interruption = None

    rule = MockRule()
    tx = MockTransaction()

    # Should not interrupt transaction (disabled for security)
    action.evaluate(rule, tx)
    assert tx.interruption is None


def test_setenv_action():
    """Test setenv action functionality."""
    action = SetEnvAction()

    assert action.action_type() == ActionType.NONDISRUPTIVE

    # Test initialization
    action.init({}, "TEST_VAR=test_value")
    assert action.var_name == "TEST_VAR"
    assert action.var_value == "test_value"

    # Test with invalid format
    try:
        action.init({}, "INVALID_FORMAT")
        assert False, "Should raise ValueError for invalid format"
    except ValueError:
        pass

    try:
        action.init({}, "")
        assert False, "Should raise ValueError for empty data"
    except ValueError:
        pass

    # Test evaluation
    class MockRule:
        def __init__(self):
            self.id = 123

    class MockTransaction:
        pass

    rule = MockRule()
    tx = MockTransaction()

    action.evaluate(rule, tx)
    assert os.environ.get("TEST_VAR") == "test_value"

    # Clean up
    if "TEST_VAR" in os.environ:
        del os.environ["TEST_VAR"]


def test_expirevar_action():
    """Test expirevar action functionality."""
    action = ExpireVarAction()

    assert action.action_type() == ActionType.NONDISRUPTIVE

    # Test initialization
    action.init({}, "session_id=3600")
    assert action.var_name == "session_id"
    assert action.expire_seconds == 3600

    # Test with invalid format
    try:
        action.init({}, "INVALID_FORMAT")
        assert False, "Should raise ValueError for invalid format"
    except ValueError:
        pass

    try:
        action.init({}, "VAR=not_a_number")
        assert False, "Should raise ValueError for non-numeric seconds"
    except ValueError:
        pass

    # Test evaluation
    class MockRule:
        def __init__(self):
            self.id = 123

    class MockTransaction:
        pass

    rule = MockRule()
    tx = MockTransaction()

    # Should not interrupt transaction
    action.evaluate(rule, tx)


def test_initcol_action():
    """Test initcol action functionality."""
    action = InitColAction()

    assert action.action_type() == ActionType.NONDISRUPTIVE

    # Test initialization
    action.init({}, "ip=%{REMOTE_ADDR}")
    assert action.collection_name == "ip"
    assert action.key_expression == "%{REMOTE_ADDR}"

    # Test with empty spec should raise error
    try:
        action.init({}, "")
        assert False, "Should raise ValueError for empty spec"
    except ValueError:
        pass

    # Test evaluation
    from lewaf.primitives.collections import TransactionVariables

    class MockRule:
        def __init__(self):
            self.id = 123

    class MockTransaction:
        def __init__(self):
            self.variables = TransactionVariables()
            self.variables.remote_addr.set("192.168.1.100")

    rule = MockRule()
    tx = MockTransaction()

    # Should not interrupt transaction (creates collection manager and IP collection)
    action.evaluate(rule, tx)

    # Verify IP collection was created
    assert hasattr(tx.variables, "ip")


def test_action_error_handling():
    """Test action error handling."""
    # Test that actions handle errors gracefully
    actions_to_test = [
        (RedirectAction(), ""),
        (SkipAction(), "invalid"),
        (RevAction(), ""),
        (SetEnvAction(), "invalid"),
        (ExpireVarAction(), "invalid"),
        (InitColAction(), ""),
    ]

    for action, invalid_data in actions_to_test:
        try:
            action.init({}, invalid_data)
            assert False, (
                f"Action {type(action).__name__} should raise ValueError for invalid data"
            )
        except ValueError:
            # Expected behavior
            pass
        except Exception as e:
            assert False, (
                f"Action {type(action).__name__} raised unexpected exception: {e}"
            )
