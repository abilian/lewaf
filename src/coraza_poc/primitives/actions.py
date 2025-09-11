from enum import IntEnum
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from coraza_poc.rules import Rule
    from coraza_poc.transaction import Transaction

ACTIONS = {}


class ActionType(IntEnum):
    """Action types matching Go implementation."""

    METADATA = 1
    DISRUPTIVE = 2
    DATA = 3
    NONDISRUPTIVE = 4
    FLOW = 5


class Action:
    """Base class for rule actions."""

    def __init__(self, argument: Optional[str] = None):
        self.argument = argument

    def init(self, rule_metadata: dict, data: str) -> None:
        """Initialize the action with rule metadata and data."""
        if data and len(data) > 0:
            raise ValueError(f"Unexpected arguments for {self.__class__.__name__}")

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        """Evaluate the action."""
        raise NotImplementedError

    def action_type(self) -> ActionType:
        """Return the type of this action."""
        raise NotImplementedError


def register_action(name: str):
    """Register an action by name."""

    def decorator(cls):
        ACTIONS[name.lower()] = cls
        return cls

    return decorator


@register_action("log")
class LogAction(Action):
    """Log action for rule matches."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        import logging

        logging.info(f"Rule {rule.id} matched and logged.")


@register_action("deny")
class DenyAction(Action):
    """Deny action that blocks the request."""

    def action_type(self) -> ActionType:
        return ActionType.DISRUPTIVE

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        import logging

        logging.warning(f"Executing DENY action from rule {rule.id}")
        transaction.interrupt(rule)


@register_action("allow")
class AllowAction(Action):
    """Allow action that permits the request."""

    def action_type(self) -> ActionType:
        return ActionType.DISRUPTIVE

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        import logging

        logging.info(f"Rule {rule.id} allowing request")
        # Allow doesn't interrupt, it just permits


@register_action("block")
class BlockAction(Action):
    """Block action that blocks the request."""

    def action_type(self) -> ActionType:
        return ActionType.DISRUPTIVE

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        import logging

        logging.warning(f"Blocking request due to rule {rule.id}")
        transaction.interrupt(rule)


@register_action("id")
class IdAction(Action):
    """ID action provides metadata about the rule."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """ID action requires an argument."""
        if not data:
            raise ValueError("ID action requires an ID argument")
        try:
            self.rule_id = int(data)
        except ValueError as e:
            raise ValueError(f"ID must be a valid integer: {data}") from e

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        pass  # ID is metadata, no runtime behavior


@register_action("phase")
class PhaseAction(Action):
    """Phase action specifies when the rule should run."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Phase action requires a phase number."""
        if not data:
            raise ValueError("Phase action requires a phase number")
        try:
            phase = int(data)
            if phase not in (1, 2, 3, 4, 5):
                raise ValueError(f"Phase must be 1-5, got {phase}")
            self.phase = phase
        except ValueError as e:
            raise ValueError(f"Phase must be a valid integer 1-5: {data}") from e

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        pass  # Phase is metadata, no runtime behavior


@register_action("msg")
class MsgAction(Action):
    """Message action provides a description for the rule."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Message action requires a message."""
        if not data:
            raise ValueError("Message action requires a message")
        self.message = data

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        pass  # Message is metadata, no runtime behavior


@register_action("severity")
class SeverityAction(Action):
    """Severity action specifies the rule severity."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Severity action requires a severity level."""
        if not data:
            raise ValueError("Severity action requires a severity level")
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
        if data.lower() not in valid_severities:
            raise ValueError(
                f"Invalid severity '{data}', must be one of: {valid_severities}"
            )
        self.severity = data.lower()

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        pass  # Severity is metadata, no runtime behavior
