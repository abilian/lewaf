"""Unit tests for basic actions (log, deny, allow, block, etc.)."""

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


def test_log_action():
    """Test log action functionality."""
    action = LogAction()

    assert action.action_type() == ActionType.NONDISRUPTIVE

    # Mock rule and transaction
    class MockRule:
        def __init__(self):
            self.id = 123

    class MockTransaction:
        pass

    rule = MockRule()
    tx = MockTransaction()

    # Should not raise exception
    action.evaluate(rule, tx)


def test_deny_action():
    """Test deny action functionality."""
    action = DenyAction()

    assert action.action_type() == ActionType.DISRUPTIVE

    class MockRule:
        def __init__(self):
            self.id = 456

    class MockTransaction:
        def __init__(self):
            self.interruption = None

        def interrupt(self, rule):
            self.interruption = {"rule_id": rule.id, "action": "deny"}

    rule = MockRule()
    tx = MockTransaction()

    action.evaluate(rule, tx)
    assert tx.interruption is not None
    assert tx.interruption["rule_id"] == 456
    assert tx.interruption["action"] == "deny"


def test_allow_action():
    """Test allow action functionality."""
    action = AllowAction()

    assert action.action_type() == ActionType.DISRUPTIVE

    class MockRule:
        def __init__(self):
            self.id = 789

    class MockTransaction:
        def __init__(self):
            self.interruption = None

        def interrupt(self, rule):
            self.interruption = {"rule_id": rule.id, "action": "allow"}

    rule = MockRule()
    tx = MockTransaction()

    action.evaluate(rule, tx)
    # Allow action doesn't interrupt - it just permits the request
    assert tx.interruption is None


def test_block_action():
    """Test block action functionality."""
    action = BlockAction()

    assert action.action_type() == ActionType.DISRUPTIVE

    class MockRule:
        def __init__(self):
            self.id = 999

    class MockTransaction:
        def __init__(self):
            self.interruption = None

        def interrupt(self, rule):
            self.interruption = {"rule_id": rule.id, "action": "block"}

    rule = MockRule()
    tx = MockTransaction()

    action.evaluate(rule, tx)
    assert tx.interruption is not None
    assert tx.interruption["action"] == "block"


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
        assert False, "Should raise ValueError for empty ID"
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
        assert False, "Should raise ValueError for invalid phase"
    except ValueError:
        pass

    try:
        action.init({}, "6")
        assert False, "Should raise ValueError for invalid phase"
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
        assert False, "Should raise ValueError for empty message"
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
        assert False, "Should raise ValueError for invalid severity"
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
        assert action_type in [
            ActionType.DISRUPTIVE,
            ActionType.NONDISRUPTIVE,
            ActionType.METADATA,
        ]
