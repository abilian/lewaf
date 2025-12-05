"""Unit tests for basic actions (log, deny, allow, block, etc.)."""

from __future__ import annotations

from lewaf.primitives.actions import (
    ACTIONS,
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


def test_action_registry():
    """Test that basic actions are registered."""
    assert "log" in ACTIONS
    assert "deny" in ACTIONS
    assert "allow" in ACTIONS
    assert "block" in ACTIONS
    assert "id" in ACTIONS
    assert "phase" in ACTIONS
    assert "msg" in ACTIONS
    assert "severity" in ACTIONS


def test_log_action(mock_rule, mock_transaction):
    """Test log action functionality."""
    action = LogAction()

    assert action.action_type() == ActionType.NONDISRUPTIVE

    # Should not raise exception
    action.evaluate(mock_rule, mock_transaction)


def test_deny_action(mock_rule, mock_transaction):
    """Test deny action functionality."""
    action = DenyAction()

    assert action.action_type() == ActionType.DISRUPTIVE

    action.evaluate(mock_rule, mock_transaction)
    assert mock_transaction._interrupted is True


def test_allow_action(mock_rule, mock_transaction):
    """Test allow action functionality."""
    action = AllowAction()

    assert action.action_type() == ActionType.DISRUPTIVE

    action.evaluate(mock_rule, mock_transaction)
    # Allow action doesn't interrupt - it just permits the request
    assert mock_transaction._interrupted is False


def test_block_action(mock_rule, mock_transaction):
    """Test block action functionality."""
    action = BlockAction()

    assert action.action_type() == ActionType.DISRUPTIVE

    action.evaluate(mock_rule, mock_transaction)
    assert mock_transaction._interrupted is True


def test_id_action():
    """Test ID action functionality."""
    action = IdAction()

    assert action.action_type() == ActionType.METADATA

    # Test initialization
    action.init({}, "12345")
    assert action.rule_id == 12345  # ID is stored as integer

    # Test with empty data should raise error
    try:
        action.init({}, "")
        msg = "Should raise ValueError for empty ID"
        raise AssertionError(msg)
    except ValueError:
        pass


def test_phase_action():
    """Test phase action functionality."""
    action = PhaseAction()

    assert action.action_type() == ActionType.METADATA

    # Test valid phases
    for phase in ["1", "2", "3", "4", "5"]:
        action.init({}, phase)
        assert action.phase == int(phase)

    # Test invalid phase
    try:
        action.init({}, "0")
        msg = "Should raise ValueError for invalid phase"
        raise AssertionError(msg)
    except ValueError:
        pass

    try:
        action.init({}, "6")
        msg = "Should raise ValueError for invalid phase"
        raise AssertionError(msg)
    except ValueError:
        pass


def test_msg_action():
    """Test message action functionality."""
    action = MsgAction()

    assert action.action_type() == ActionType.METADATA

    # Test initialization
    action.init({}, "Test message")
    assert action.message == "Test message"

    # Test with empty message should raise error
    try:
        action.init({}, "")
        msg = "Should raise ValueError for empty message"
        raise AssertionError(msg)
    except ValueError:
        pass


def test_severity_action():
    """Test severity action functionality."""
    action = SeverityAction()

    assert action.action_type() == ActionType.METADATA

    # Test valid severities (stored in lowercase)
    valid_severities = [
        "EMERGENCY",
        "ALERT",
        "CRITICAL",
        "ERROR",
        "WARNING",
        "NOTICE",
        "INFO",
        "DEBUG",
    ]
    for severity in valid_severities:
        action.init({}, severity)
        assert action.severity == severity.lower()  # Implementation stores in lowercase

    # Test invalid severity
    try:
        action.init({}, "INVALID")
        msg = "Should raise ValueError for invalid severity"
        raise AssertionError(msg)
    except ValueError:
        pass


def test_action_types():
    """Test action type enumeration."""
    assert ActionType.DISRUPTIVE != ActionType.NONDISRUPTIVE
    assert ActionType.DISRUPTIVE != ActionType.METADATA
    assert ActionType.NONDISRUPTIVE != ActionType.METADATA

    # Test that types can be compared
    assert ActionType.DISRUPTIVE == ActionType.DISRUPTIVE
    assert ActionType.NONDISRUPTIVE == ActionType.NONDISRUPTIVE
    assert ActionType.METADATA == ActionType.METADATA


def test_action_inheritance():
    """Test that actions properly inherit from base Action class."""
    actions = [
        LogAction(),
        DenyAction(),
        AllowAction(),
        BlockAction(),
        IdAction(),
        PhaseAction(),
        MsgAction(),
        SeverityAction(),
    ]

    for action in actions:
        # All actions should have action_type method
        assert hasattr(action, "action_type")
        assert callable(action.action_type)

        # All actions should have evaluate method
        assert hasattr(action, "evaluate")
        assert callable(action.evaluate)

        # Action type should be one of the valid types
        action_type = action.action_type()
        assert action_type in {
            ActionType.DISRUPTIVE,
            ActionType.NONDISRUPTIVE,
            ActionType.METADATA,
        }
