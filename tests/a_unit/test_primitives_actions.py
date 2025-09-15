from __future__ import annotations

import pytest

from coraza_poc.primitives.actions import (
    ACTIONS,
    Action,
    ActionType,
    AllowAction,
    BlockAction,
    DenyAction,
    IdAction,
    LogAction,
    MsgAction,
    PhaseAction,
    SeverityAction,
)


class MockRule:
    """Mock rule for testing actions."""

    def __init__(self, rule_id=1):
        self.id = rule_id


class MockTransaction:
    """Mock transaction for testing actions."""

    def __init__(self):
        self.interruption: dict[str, str | int] | None = None
        self.logs = []

    def interrupt(self, rule):
        self.interruption = {"rule_id": rule.id, "action": "deny"}


def test_action_types():
    """Tests ActionType enum values match Go implementation."""
    assert ActionType.METADATA == 1
    assert ActionType.DISRUPTIVE == 2
    assert ActionType.DATA == 3
    assert ActionType.NONDISRUPTIVE == 4
    assert ActionType.FLOW == 5


def test_log_action():
    """Tests LogAction functionality."""
    action = LogAction()
    rule = MockRule(123)
    tx = MockTransaction()

    # Test action type
    assert action.action_type() == ActionType.NONDISRUPTIVE

    # Test init (should not accept arguments)
    action.init({}, "")
    with pytest.raises(ValueError, match="Unexpected arguments"):
        action.init({}, "unexpected")

    # Test evaluate (no exceptions should be raised)
    action.evaluate(rule, tx)
    assert tx.interruption is None  # Non-disruptive


def test_deny_action():
    """Tests DenyAction functionality."""
    action = DenyAction()
    rule = MockRule(456)
    tx = MockTransaction()

    # Test action type
    assert action.action_type() == ActionType.DISRUPTIVE

    # Test init
    action.init({}, "")

    # Test evaluate
    action.evaluate(rule, tx)
    assert tx.interruption is not None
    assert tx.interruption["rule_id"] == 456


def test_allow_action():
    """Tests AllowAction functionality."""
    action = AllowAction()
    rule = MockRule(789)
    tx = MockTransaction()

    # Test action type
    assert action.action_type() == ActionType.DISRUPTIVE

    # Test evaluate (should not interrupt)
    action.evaluate(rule, tx)
    assert tx.interruption is None  # Allow doesn't interrupt


def test_block_action():
    """Tests BlockAction functionality."""
    action = BlockAction()
    rule = MockRule(999)
    tx = MockTransaction()

    # Test action type
    assert action.action_type() == ActionType.DISRUPTIVE

    # Test evaluate
    action.evaluate(rule, tx)
    assert tx.interruption is not None


def test_id_action():
    """Tests IdAction functionality."""
    action = IdAction()

    # Test action type
    assert action.action_type() == ActionType.METADATA

    # Test init with valid ID
    action.init({}, "12345")
    assert action.rule_id == 12345

    # Test init with invalid ID
    with pytest.raises(ValueError, match="ID must be a valid integer"):
        action.init({}, "invalid")

    # Test init without ID
    with pytest.raises(ValueError, match="ID action requires an ID argument"):
        action.init({}, "")

    # Test evaluate (metadata actions do nothing at runtime)
    rule = MockRule()
    tx = MockTransaction()
    action.evaluate(rule, tx)


def test_phase_action():
    """Tests PhaseAction functionality."""
    action = PhaseAction()

    # Test action type
    assert action.action_type() == ActionType.METADATA

    # Test init with valid phases
    for phase in [1, 2, 3, 4, 5]:
        action.init({}, str(phase))
        assert action.phase == phase

    # Test init with invalid phase
    with pytest.raises(ValueError, match="Phase must be a valid integer 1-5"):
        action.init({}, "6")

    with pytest.raises(ValueError, match="Phase must be a valid integer 1-5"):
        action.init({}, "invalid")

    # Test init without phase
    with pytest.raises(ValueError, match="Phase action requires a phase number"):
        action.init({}, "")


def test_msg_action():
    """Tests MsgAction functionality."""
    action = MsgAction()

    # Test action type
    assert action.action_type() == ActionType.METADATA

    # Test init with message
    action.init({}, "This is a test message")
    assert action.message == "This is a test message"

    # Test init without message
    with pytest.raises(ValueError, match="Message action requires a message"):
        action.init({}, "")


def test_severity_action():
    """Tests SeverityAction functionality."""
    action = SeverityAction()

    # Test action type
    assert action.action_type() == ActionType.METADATA

    # Test init with valid severities
    valid_severities = [
        "emergency",
        "alert",
        "critical",
        "error",
        "warning",
        "notice",
        "info",
        "debug",
    ]
    for severity in valid_severities:
        action.init({}, severity)
        assert action.severity == severity.lower()

        # Test case insensitivity
        action.init({}, severity.upper())
        assert action.severity == severity.lower()

    # Test init with invalid severity
    with pytest.raises(ValueError, match="Invalid severity"):
        action.init({}, "invalid")

    # Test init without severity
    with pytest.raises(ValueError, match="Severity action requires a severity level"):
        action.init({}, "")


def test_action_registry():
    """Tests that actions are properly registered."""
    expected_actions = [
        "log",
        "deny",
        "allow",
        "block",
        "id",
        "phase",
        "msg",
        "severity",
    ]

    for action_name in expected_actions:
        assert action_name in ACTIONS
        action_class = ACTIONS[action_name]
        action_instance = action_class()
        assert isinstance(action_instance, Action)


def test_action_base_class():
    """Tests Action base class behavior."""

    class TestAction(Action):
        def action_type(self):
            return ActionType.METADATA

        def evaluate(self, rule, transaction):
            pass

    action = TestAction("test_arg")
    assert action.argument == "test_arg"

    # Test default init behavior
    action.init({}, "")  # Should not raise

    # Test with argument when not expected
    with pytest.raises(ValueError, match="Unexpected arguments"):
        action.init({}, "unexpected")


def test_action_factory_pattern():
    """Tests action creation through registry."""
    # Test creating actions from registry
    log_action = ACTIONS["log"]()
    assert isinstance(log_action, LogAction)

    deny_action = ACTIONS["deny"]()
    assert isinstance(deny_action, DenyAction)

    id_action = ACTIONS["id"]()
    assert isinstance(id_action, IdAction)


def test_action_type_inheritance():
    """Tests that all actions properly implement action_type method."""
    test_cases = [
        (LogAction(), ActionType.NONDISRUPTIVE),
        (DenyAction(), ActionType.DISRUPTIVE),
        (AllowAction(), ActionType.DISRUPTIVE),
        (BlockAction(), ActionType.DISRUPTIVE),
        (IdAction(), ActionType.METADATA),
        (PhaseAction(), ActionType.METADATA),
        (MsgAction(), ActionType.METADATA),
        (SeverityAction(), ActionType.METADATA),
    ]

    for action, expected_type in test_cases:
        assert action.action_type() == expected_type
