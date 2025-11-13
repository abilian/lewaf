"""Unit tests for Phase 6 actions (transformation action 't')."""

from __future__ import annotations

import pytest

from lewaf.primitives.actions import ACTIONS, ActionType, TransformationAction


def test_transformation_action_registered():
    """Test that 't' transformation action is registered."""
    assert "t" in ACTIONS
    assert ACTIONS["t"] == TransformationAction


def test_transformation_action_type():
    """Test transformation action type."""
    action = TransformationAction()
    assert action.action_type() == ActionType.NONDISRUPTIVE


def test_transformation_action_adds_transformation():
    """Test that 't' action adds transformations to rule metadata."""
    action = TransformationAction()

    rule_metadata = {}
    action.init(rule_metadata, "lowercase")

    assert "transformations" in rule_metadata
    assert "lowercase" in rule_metadata["transformations"]


def test_transformation_action_multiple_transformations():
    """Test adding multiple transformations."""
    action1 = TransformationAction()
    action2 = TransformationAction()
    action3 = TransformationAction()

    rule_metadata = {}
    action1.init(rule_metadata, "lowercase")
    action2.init(rule_metadata, "trim")
    action3.init(rule_metadata, "removewhitespace")

    assert rule_metadata["transformations"] == [
        "lowercase",
        "trim",
        "removewhitespace",
    ]


def test_transformation_action_none_clears():
    """Test that 't:none' clears all previous transformations."""
    # Add some transformations first
    rule_metadata = {"transformations": ["uppercase", "trim", "removewhitespace"]}

    # Apply t:none
    action = TransformationAction()
    action.init(rule_metadata, "none")

    assert rule_metadata["transformations"] == []


def test_transformation_action_none_then_add():
    """Test clearing transformations and then adding new ones."""
    rule_metadata = {"transformations": ["uppercase", "trim"]}

    # Clear with t:none
    action1 = TransformationAction()
    action1.init(rule_metadata, "none")
    assert rule_metadata["transformations"] == []

    # Add new transformations
    action2 = TransformationAction()
    action2.init(rule_metadata, "lowercase")
    assert rule_metadata["transformations"] == ["lowercase"]


def test_transformation_action_invalid_transformation():
    """Test that invalid transformation name raises ValueError."""
    action = TransformationAction()
    rule_metadata = {}

    with pytest.raises(
        ValueError, match=r"Unknown transformation.*invalidtransformationname"
    ):
        action.init(rule_metadata, "invalidtransformationname")


def test_transformation_action_empty_data():
    """Test that empty transformation name raises ValueError."""
    action = TransformationAction()
    rule_metadata = {}

    with pytest.raises(ValueError, match="requires a transformation name"):
        action.init(rule_metadata, "")


def test_transformation_action_evaluate_noop():
    """Test that evaluate does nothing (transformations applied during rule evaluation)."""

    class MockRule:
        def __init__(self):
            self.id = 1

    class MockTransaction:
        pass

    action = TransformationAction()
    rule = MockRule()
    tx = MockTransaction()

    # Should not raise exception
    action.evaluate(rule, tx)


def test_transformation_action_case_insensitive():
    """Test that transformation names are case-insensitive."""
    action = TransformationAction()
    rule_metadata = {}

    # Uppercase transformation name should be converted to lowercase
    action.init(rule_metadata, "LOWERCASE")
    assert "lowercase" in rule_metadata["transformations"]


def test_transformation_action_whitespace_handling():
    """Test that transformation names with whitespace are stripped."""
    action = TransformationAction()
    rule_metadata = {}

    action.init(rule_metadata, "  lowercase  ")
    assert "lowercase" in rule_metadata["transformations"]
