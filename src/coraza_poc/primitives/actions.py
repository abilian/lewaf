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


@register_action("pass")
class PassAction(Action):
    """Pass action allows the request to continue."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        import logging

        logging.debug(f"Rule {rule.id} matched but allowed to pass")
        # Pass action does nothing - just allows the request to continue


@register_action("nolog")
class NoLogAction(Action):
    """No log action prevents logging."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        # This action prevents logging, handled at framework level
        pass


@register_action("logdata")
class LogDataAction(Action):
    """Log data action specifies what data to log."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """LogData action can have optional data specification."""
        self.log_data = data or ""

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        pass  # Metadata only


@register_action("capture")
class CaptureAction(Action):
    """Capture action for capturing matched groups."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        # Capture functionality handled by operators
        pass


@register_action("setvar")
class SetVarAction(Action):
    """Set variable action for setting transaction variables."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def init(self, rule_metadata: dict, data: str) -> None:
        """SetVar action requires variable specification."""
        if not data:
            raise ValueError("SetVar action requires variable specification")
        self.var_spec = data

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        # Parse variable specification (e.g., "tx.anomaly_score=+5")
        import logging

        logging.debug(f"Setting variable: {self.var_spec}")
        # Variable setting logic would go here


@register_action("ctl")
class CtlAction(Action):
    """Control action for runtime control settings."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def init(self, rule_metadata: dict, data: str) -> None:
        """Ctl action requires control specification."""
        if not data:
            raise ValueError("Ctl action requires control specification")
        self.control_spec = data

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        # Parse control specification (e.g., "ruleRemoveTargetByID=123;ARGS:foo")
        import logging

        logging.debug(f"Control setting: {self.control_spec}")
        # Control logic would go here


@register_action("skipafter")
class SkipAfterAction(Action):
    """Skip after action for conditional rule skipping."""

    def action_type(self) -> ActionType:
        return ActionType.FLOW

    def init(self, rule_metadata: dict, data: str) -> None:
        """SkipAfter action requires a marker."""
        if not data:
            raise ValueError("SkipAfter action requires a marker")
        self.marker = data

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        # Skip logic handled by rule engine
        pass


@register_action("tag")
class TagAction(Action):
    """Tag action for adding tags to rules."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Tag action requires a tag name."""
        if not data:
            raise ValueError("Tag action requires a tag name")
        self.tag_name = data

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        pass  # Tags are metadata only


@register_action("ver")
class VerAction(Action):
    """Version action for rule versioning."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Ver action requires a version string."""
        if not data:
            raise ValueError("Ver action requires a version string")
        self.version = data

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        pass  # Version is metadata only


@register_action("maturity")
class MaturityAction(Action):
    """Maturity action for rule maturity level."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Maturity action requires a maturity level."""
        if not data:
            raise ValueError("Maturity action requires a maturity level")
        try:
            self.maturity = int(data)
        except ValueError as e:
            raise ValueError(f"Maturity must be an integer: {data}") from e

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        pass  # Maturity is metadata only


@register_action("accuracy")
class AccuracyAction(Action):
    """Accuracy action for rule accuracy level."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Accuracy action requires an accuracy level."""
        if not data:
            raise ValueError("Accuracy action requires an accuracy level")
        try:
            self.accuracy = int(data)
        except ValueError as e:
            raise ValueError(f"Accuracy must be an integer: {data}") from e

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        pass  # Accuracy is metadata only


@register_action("chain")
class ChainAction(Action):
    """Chain action for linking rules together."""

    def action_type(self) -> ActionType:
        return ActionType.FLOW

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        # Chain logic handled by rule engine
        pass


@register_action("multimatch")
class MultiMatchAction(Action):
    """Multi-match action for multiple pattern matching."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        # Multi-match logic handled by operators
        pass


@register_action("status")
class StatusAction(Action):
    """Status action for HTTP response status."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Status action requires a status code."""
        if not data:
            raise ValueError("Status action requires a status code")
        try:
            self.status_code = int(data)
        except ValueError as e:
            raise ValueError(f"Status must be an integer: {data}") from e

    def evaluate(self, rule: "Rule", transaction: "Transaction") -> None:
        pass  # Status is metadata only
