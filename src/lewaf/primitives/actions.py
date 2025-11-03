from __future__ import annotations

import re
import time
from enum import IntEnum
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    pass


class RuleProtocol(Protocol):
    """Protocol defining the minimal rule interface needed by actions."""

    id: int | str


class TransactionProtocol(Protocol):
    """Protocol defining the minimal transaction interface needed by actions."""

    def interrupt(self, rule: RuleProtocol) -> None:
        """Interrupt the transaction with the given rule."""
        ...


class MacroExpander:
    """Advanced macro and variable expansion system for ModSecurity-style expressions."""

    @staticmethod
    def expand(expression: str, transaction: TransactionProtocol) -> str:
        """Expand macros and variables in an expression.

        Supports various macro types:
        - %{VAR_NAME} - Simple variable references
        - %{REQUEST_HEADERS.host} - Collection member access
        - %{TX.score} - Transaction variables
        - %{ENV.HOME} - Environment variables
        - %{TIME} - Current timestamp
        - %{TIME_SEC} - Current timestamp in seconds
        - %{UNIQUE_ID} - Transaction unique ID
        """
        # Handle variable references like %{VAR_NAME}
        var_pattern = re.compile(r"%\{([^}]+)\}")

        def replace_var(match):
            var_spec = match.group(1)
            return MacroExpander._resolve_variable(var_spec, transaction)

        resolved = var_pattern.sub(replace_var, expression)
        return resolved

    @staticmethod
    def _resolve_variable(var_spec: str, transaction: TransactionProtocol) -> str:
        """Resolve a single variable specification."""
        var_spec = var_spec.upper()

        # Handle collection member access (e.g., REQUEST_HEADERS.host)
        if "." in var_spec:
            collection_name, member_key = var_spec.split(".", 1)
            return MacroExpander._resolve_collection_member(
                collection_name, member_key, transaction
            )

        # Handle special variables
        if var_spec == "MATCHED_VAR":
            return getattr(transaction, "matched_var", "0")
        elif var_spec == "MATCHED_VAR_NAME":
            return getattr(transaction, "matched_var_name", "")
        elif var_spec == "TIME":
            return str(int(time.time() * 1000))  # Milliseconds
        elif var_spec == "TIME_SEC":
            return str(int(time.time()))  # Seconds
        elif var_spec == "UNIQUE_ID":
            return (
                transaction.variables.unique_id.get()
                if hasattr(transaction, "variables")
                else ""
            )
        elif var_spec == "REQUEST_URI":
            return (
                transaction.variables.request_uri.get()
                if hasattr(transaction, "variables")
                else ""
            )
        elif var_spec == "REQUEST_METHOD":
            return (
                transaction.variables.request_method.get()
                if hasattr(transaction, "variables")
                else ""
            )
        elif var_spec == "REMOTE_ADDR":
            return (
                transaction.variables.remote_addr.get()
                if hasattr(transaction, "variables")
                else ""
            )
        elif var_spec == "SERVER_NAME":
            return (
                transaction.variables.server_name.get()
                if hasattr(transaction, "variables")
                else ""
            )

        # Default return for unknown variables
        return ""

    @staticmethod
    def _resolve_collection_member(
        collection_name: str, member_key: str, transaction: TransactionProtocol
    ) -> str:
        """Resolve a collection member access."""
        if not hasattr(transaction, "variables"):
            return ""

        collection_name = collection_name.upper()
        member_key = member_key.lower()

        # Handle different collection types
        if collection_name == "TX":
            values = transaction.variables.tx.get(member_key)
            return values[0] if values else ""
        elif collection_name == "REQUEST_HEADERS":
            values = transaction.variables.request_headers.get(member_key)
            return values[0] if values else ""
        elif collection_name == "RESPONSE_HEADERS":
            values = transaction.variables.response_headers.get(member_key)
            return values[0] if values else ""
        elif collection_name == "ARGS":
            values = transaction.variables.args.get(member_key)
            return values[0] if values else ""
        elif collection_name == "REQUEST_COOKIES":
            values = transaction.variables.request_cookies.get(member_key)
            return values[0] if values else ""
        elif collection_name == "ENV":
            # Environment variables
            import os

            return os.environ.get(member_key.upper(), "")
        elif collection_name == "GEO":
            values = transaction.variables.geo.get(member_key)
            return values[0] if values else ""

        return ""


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

    def __init__(self, argument: str | None = None):
        self.argument = argument

    def init(self, rule_metadata: dict, data: str) -> None:
        """Initialize the action with rule metadata and data."""
        if data and len(data) > 0:
            raise ValueError(f"Unexpected arguments for {self.__class__.__name__}")

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
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

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        import logging

        logging.info(f"Rule {rule.id} matched and logged.")


@register_action("deny")
class DenyAction(Action):
    """Deny action that blocks the request."""

    def action_type(self) -> ActionType:
        return ActionType.DISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        import logging

        logging.warning(f"Executing DENY action from rule {rule.id}")
        transaction.interrupt(rule)


@register_action("allow")
class AllowAction(Action):
    """Allow action that permits the request."""

    def action_type(self) -> ActionType:
        return ActionType.DISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        import logging

        logging.info(f"Rule {rule.id} allowing request")
        # Allow doesn't interrupt, it just permits


@register_action("block")
class BlockAction(Action):
    """Block action that blocks the request."""

    def action_type(self) -> ActionType:
        return ActionType.DISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
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

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
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

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
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

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
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

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        pass  # Severity is metadata, no runtime behavior


@register_action("pass")
class PassAction(Action):
    """Pass action allows the request to continue."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        import logging

        logging.debug(f"Rule {rule.id} matched but allowed to pass")
        # Pass action does nothing - just allows the request to continue


@register_action("nolog")
class NoLogAction(Action):
    """No log action prevents logging."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
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

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        pass  # Metadata only


@register_action("capture")
class CaptureAction(Action):
    """Capture action for capturing matched groups."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        # Capture functionality handled by operators
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

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        pass  # Tags are metadata only


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

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
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

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        pass  # Accuracy is metadata only


@register_action("chain")
class ChainAction(Action):
    """Chain action for linking rules together.

    The chain action allows multiple rules to be linked together in a logical AND chain.
    If the current rule matches, the chain continues to the next rule. If any rule in the
    chain fails to match, the entire chain fails.
    """

    def action_type(self) -> ActionType:
        return ActionType.FLOW

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        # Mark this rule as starting a chain
        if not hasattr(transaction, "chain_state"):
            transaction.chain_state = {}

        transaction.chain_state["in_chain"] = True
        transaction.chain_state["chain_starter"] = rule.id
        transaction.chain_state["chain_matched"] = True  # This rule matched to get here


@register_action("skipafter")
class SkipAfterAction(Action):
    """Skip all rules after a specified rule ID or tag.

    This action causes rule processing to skip all rules that come after
    the specified rule ID or tag within the current phase.
    """

    def action_type(self) -> ActionType:
        return ActionType.FLOW

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        if not hasattr(transaction, "skip_state"):
            transaction.skip_state = {}

        # The argument can be a rule ID or tag
        if hasattr(self, "argument") and self.argument:
            if self.argument.isdigit():
                # Numeric rule ID
                transaction.skip_state["skip_after_id"] = int(self.argument)
            else:
                # Tag-based skipping
                transaction.skip_state["skip_after_tag"] = self.argument
        else:
            # Skip all remaining rules in current phase
            transaction.skip_state["skip_remaining"] = True


@register_action("skipnext")
class SkipNextAction(Action):
    """Skip the next N rules in the current phase.

    This action causes rule processing to skip the next N rules.
    If no argument is provided, skips the next rule.
    """

    def action_type(self) -> ActionType:
        return ActionType.FLOW

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        if not hasattr(transaction, "skip_state"):
            transaction.skip_state = {}

        skip_count = 1  # Default: skip next rule
        if self.argument and self.argument.isdigit():
            skip_count = int(self.argument)

        transaction.skip_state["skip_next_count"] = skip_count


@register_action("multimatch")
class MultiMatchAction(Action):
    """Multi-match action for multiple pattern matching."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        # Multi-match logic handled by operators
        if not hasattr(transaction, "multimatch_state"):
            transaction.multimatch_state = {}
        transaction.multimatch_state["enabled"] = True


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

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        pass  # Status is metadata only


@register_action("auditlog")
class AuditLogAction(Action):
    """Audit log action marks transaction for logging."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        import logging

        logging.info(f"Rule {rule.id} marked transaction for audit logging")
        # TODO: In full implementation, mark transaction for audit logging


@register_action("noauditlog")
class NoAuditLogAction(Action):
    """No audit log action prevents audit logging."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        import logging

        logging.debug(f"Rule {rule.id} disabled audit logging for transaction")
        # TODO: In full implementation, disable audit logging for transaction


@register_action("redirect")
class RedirectAction(Action):
    """Redirect action issues external redirection."""

    def action_type(self) -> ActionType:
        return ActionType.DISRUPTIVE

    def init(self, rule_metadata: dict, data: str) -> None:
        """Redirect action requires a URL."""
        if not data:
            raise ValueError("Redirect action requires a URL")
        self.redirect_url = data

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        import logging

        logging.warning(f"Rule {rule.id} redirecting to {self.redirect_url}")
        transaction.interrupt(rule)
        # TODO: In full implementation, set redirect response


@register_action("skip")
class SkipAction(Action):
    """Skip action skips one or more rules."""

    def action_type(self) -> ActionType:
        return ActionType.FLOW

    def init(self, rule_metadata: dict, data: str) -> None:
        """Skip action requires number of rules to skip."""
        if not data:
            raise ValueError("Skip action requires number of rules to skip")
        try:
            self.skip_count = int(data)
        except ValueError as e:
            raise ValueError(f"Skip count must be an integer: {data}") from e

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        import logging

        logging.debug(f"Rule {rule.id} skipping {self.skip_count} rules")
        # TODO: In full implementation, skip the specified number of rules


@register_action("rev")
class RevAction(Action):
    """Rev action specifies rule revision."""

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Rev action requires a revision number."""
        if not data:
            raise ValueError("Rev action requires a revision number")
        self.revision = data

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        pass  # Revision is metadata only


@register_action("drop")
class DropAction(Action):
    """Drop action terminates connection."""

    def action_type(self) -> ActionType:
        return ActionType.DISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        import logging

        logging.warning(f"Rule {rule.id} dropping connection")
        transaction.interrupt(rule)
        # TODO: In full implementation, terminate the connection


@register_action("exec")
class ExecAction(Action):
    """Exec action executes external command (SECURITY RISK)."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def init(self, rule_metadata: dict, data: str) -> None:
        """Exec action requires a command."""
        if not data:
            raise ValueError("Exec action requires a command")
        self.command = data

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        import logging

        # WARNING: exec action is a significant security risk
        # In production, this should be heavily restricted or disabled
        logging.warning(f"Rule {rule.id} would execute: {self.command}")
        logging.warning("SECURITY WARNING: exec action disabled for safety")
        # TODO: In full implementation with proper security controls:
        # subprocess.run(self.command, shell=True, timeout=10)


@register_action("setenv")
class SetEnvAction(Action):
    """SetEnv action sets environment variables."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def init(self, rule_metadata: dict, data: str) -> None:
        """SetEnv action requires var=value format."""
        if not data or "=" not in data:
            raise ValueError("SetEnv action requires var=value format")
        parts = data.split("=", 1)
        self.var_name = parts[0].strip()
        self.var_value = parts[1].strip()

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        import os
        import logging

        logging.debug(f"Rule {rule.id} setting env {self.var_name}={self.var_value}")
        os.environ[self.var_name] = self.var_value


@register_action("initcol")
class InitColAction(Action):
    """InitCol action initializes persistent collection."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def init(self, rule_metadata: dict, data: str) -> None:
        """InitCol action requires collection specification."""
        if not data:
            raise ValueError("InitCol action requires collection specification")
        self.collection_spec = data

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        import logging

        logging.debug(f"Rule {rule.id} initializing collection: {self.collection_spec}")
        # TODO: In full implementation, initialize persistent collection


@register_action("setvar")
class SetVarAction(Action):
    """Set or modify transaction variables.

    Supports operations like:
    - setvar:tx.score=+5 (increment)
    - setvar:tx.anomaly_score=-%{MATCHED_VAR} (decrement by variable)
    - setvar:tx.blocked=1 (assign)
    - setvar:!tx.temp_var (delete variable)
    """

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def init(self, rule_metadata: dict, data: str) -> None:
        """Parse setvar expression."""
        if not data:
            raise ValueError("SetVar action requires variable specification")
        self.var_spec = data

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        spec = self.var_spec.strip()

        # Handle variable deletion (prefixed with !)
        if spec.startswith("!"):
            var_name = spec[1:]
            self._delete_variable(var_name, transaction)
            return

        # Parse assignment/operation
        if "=" in spec:
            var_name, expression = spec.split("=", 1)
            var_name = var_name.strip()
            expression = expression.strip()

            # Handle different operations
            if expression.startswith("+"):
                # Increment operation
                increment_value = self._resolve_expression(expression[1:], transaction)
                self._increment_variable(var_name, increment_value, transaction)
            elif expression.startswith("-"):
                # Decrement operation
                decrement_value = self._resolve_expression(expression[1:], transaction)
                self._decrement_variable(var_name, decrement_value, transaction)
            else:
                # Direct assignment
                value = self._resolve_expression(expression, transaction)
                self._set_variable(var_name, value, transaction)

    def _resolve_expression(
        self, expression: str, transaction: TransactionProtocol
    ) -> str:
        """Resolve variable references and macros in expressions."""
        return MacroExpander.expand(expression, transaction)

    def _set_variable(
        self, var_name: str, value: str, transaction: TransactionProtocol
    ) -> None:
        """Set a transaction variable."""
        if var_name.startswith("tx."):
            tx_var = var_name[3:].lower()
            transaction.variables.tx.remove(tx_var)  # Clear existing
            transaction.variables.tx.add(tx_var, value)

    def _increment_variable(
        self, var_name: str, increment: str, transaction: TransactionProtocol
    ) -> None:
        """Increment a numeric transaction variable."""
        if var_name.startswith("tx."):
            tx_var = var_name[3:].lower()
            current_values = transaction.variables.tx.get(tx_var)
            current_value = int(current_values[0]) if current_values else 0
            increment_value = int(increment) if increment.isdigit() else 0
            new_value = current_value + increment_value

            transaction.variables.tx.remove(tx_var)
            transaction.variables.tx.add(tx_var, str(new_value))

    def _decrement_variable(
        self, var_name: str, decrement: str, transaction: TransactionProtocol
    ) -> None:
        """Decrement a numeric transaction variable."""
        if var_name.startswith("tx."):
            tx_var = var_name[3:].lower()
            current_values = transaction.variables.tx.get(tx_var)
            current_value = int(current_values[0]) if current_values else 0
            decrement_value = int(decrement) if decrement.isdigit() else 0
            new_value = current_value - decrement_value

            transaction.variables.tx.remove(tx_var)
            transaction.variables.tx.add(tx_var, str(new_value))

    def _delete_variable(self, var_name: str, transaction: TransactionProtocol) -> None:
        """Delete a transaction variable."""
        if var_name.startswith("tx."):
            tx_var = var_name[3:].lower()
            transaction.variables.tx.remove(tx_var)


@register_action("deprecatevar")
class DeprecateVarAction(Action):
    """Mark a variable as deprecated with optional expiration time."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def init(self, rule_metadata: dict, data: str) -> None:
        """Parse deprecation specification."""
        if not data:
            raise ValueError("DeprecateVar action requires variable specification")
        self.var_spec = data

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        # Mark variable as deprecated in transaction metadata
        if not hasattr(transaction, "deprecated_vars"):
            transaction.deprecated_vars = set()
        transaction.deprecated_vars.add(self.var_spec)


@register_action("expirevar")
class ExpireVarAction(Action):
    """Set expiration time for transaction variables."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def init(self, rule_metadata: dict, data: str) -> None:
        """Parse expiration specification."""
        if not data or "=" not in data:
            raise ValueError("ExpireVar action requires var=seconds format")

        parts = data.split("=", 1)
        self.var_name = parts[0].strip()
        try:
            self.expire_seconds = int(parts[1].strip())
        except ValueError as e:
            raise ValueError(f"ExpireVar seconds must be integer: {parts[1]}") from e

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        import time

        # Store expiration info
        if not hasattr(transaction, "var_expiration"):
            transaction.var_expiration = {}

        expiry_timestamp = time.time() + self.expire_seconds
        transaction.var_expiration[self.var_name] = expiry_timestamp


@register_action("conditional")
class ConditionalAction(Action):
    """Conditional action execution based on transaction state.

    Allows conditional execution of other actions based on variable values.
    Format: conditional:condition,action_list
    Example: conditional:TX.blocking_mode=1,deny:403
    """

    def action_type(self) -> ActionType:
        return ActionType.FLOW

    def init(self, rule_metadata: dict, data: str) -> None:
        """Parse conditional specification."""
        if not data or "," not in data:
            raise ValueError("Conditional action requires condition,action format")

        condition, actions_str = data.split(",", 1)
        self.condition = condition.strip()
        self.actions_str = actions_str.strip()

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        """Evaluate condition and execute actions if true."""
        if self._evaluate_condition(self.condition, transaction):
            # Parse and execute the conditional actions
            self._execute_conditional_actions(self.actions_str, rule, transaction)

    def _evaluate_condition(
        self, condition: str, transaction: TransactionProtocol
    ) -> bool:
        """Evaluate a condition expression."""

        # Handle different condition types
        if "=" in condition:
            var_name, expected_value = condition.split("=", 1)
            var_name = var_name.strip()
            expected_value = expected_value.strip()

            actual_value = self._get_variable_value(var_name, transaction)
            return actual_value == expected_value

        elif ">" in condition:
            var_name, threshold = condition.split(">", 1)
            var_name = var_name.strip()
            threshold = threshold.strip()

            actual_value = self._get_variable_value(var_name, transaction)
            try:
                return float(actual_value) > float(threshold)
            except ValueError:
                return False

        elif "<" in condition:
            var_name, threshold = condition.split("<", 1)
            var_name = var_name.strip()
            threshold = threshold.strip()

            actual_value = self._get_variable_value(var_name, transaction)
            try:
                return float(actual_value) < float(threshold)
            except ValueError:
                return False

        # Default: check if variable exists and is non-empty
        return bool(self._get_variable_value(condition, transaction))

    def _get_variable_value(
        self, var_name: str, transaction: TransactionProtocol
    ) -> str:
        """Get the value of a variable from transaction."""
        if var_name.startswith("TX."):
            tx_var = var_name[3:].lower()
            values = transaction.variables.tx.get(tx_var)
            return values[0] if values else ""
        elif var_name.startswith("GEO."):
            geo_var = var_name[4:].lower()
            values = transaction.variables.geo.get(geo_var)
            return values[0] if values else ""
        elif var_name.startswith("REMOTE_ADDR"):
            values = transaction.variables.remote_addr.get()
            return values[0] if values else ""
        elif var_name == "MATCHED_VAR":
            return getattr(transaction, "matched_var", "")
        elif var_name == "MATCHED_VAR_NAME":
            return getattr(transaction, "matched_var_name", "")
        # Add more variable types as needed
        return ""

    def _execute_conditional_actions(
        self, actions_str: str, rule: RuleProtocol, transaction: TransactionProtocol
    ) -> None:
        """Execute the conditional actions."""
        # This is a simplified implementation
        # In a full implementation, this would parse and execute actual actions
        import logging

        logging.debug(f"Conditional actions triggered: {actions_str}")


@register_action("ctl")
class CtlAction(Action):
    """Control action for runtime rule engine configuration.

    Allows dynamic control of rule engine behavior:
    - ctl:ruleEngine=Off (disable rule processing)
    - ctl:ruleEngine=DetectionOnly (detection mode only)
    - ctl:requestBodyProcessor=XML (change body processor)
    - ctl:requestBodyLimit=1048576 (change body size limit)
    """

    def action_type(self) -> ActionType:
        return ActionType.FLOW

    def init(self, rule_metadata: dict, data: str) -> None:
        """Parse control specification."""
        if not data or "=" not in data:
            raise ValueError("Ctl action requires property=value format")

        property_name, value = data.split("=", 1)
        self.property_name = property_name.strip()
        self.value = value.strip()

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        """Apply control directive to transaction."""
        if not hasattr(transaction, "ctl_directives"):
            transaction.ctl_directives = {}

        transaction.ctl_directives[self.property_name] = self.value

        # Handle specific control directives
        if self.property_name.lower() == "ruleengine":
            self._handle_rule_engine_control(transaction)
        elif self.property_name.lower() == "requestbodyprocessor":
            self._handle_body_processor_control(transaction)
        elif self.property_name.lower() == "requestbodylimit":
            self._handle_body_limit_control(transaction)

    def _handle_rule_engine_control(self, transaction: TransactionProtocol) -> None:
        """Handle rule engine control directive."""
        engine_mode = self.value.lower()
        if engine_mode == "off":
            transaction.rule_engine_enabled = False
        elif engine_mode == "detectiononly":
            transaction.rule_engine_mode = "detection"
            transaction.rule_engine_enabled = True
        elif engine_mode == "on":
            transaction.rule_engine_mode = "blocking"
            transaction.rule_engine_enabled = True

    def _handle_body_processor_control(self, transaction: TransactionProtocol) -> None:
        """Handle request body processor control."""
        transaction.body_processor = self.value.upper()

    def _handle_body_limit_control(self, transaction: TransactionProtocol) -> None:
        """Handle request body limit control."""
        try:
            transaction.body_limit = int(self.value)
        except ValueError:
            pass  # Invalid limit value


@register_action("ver")
class VerAction(Action):
    """Version action for rule compatibility checking.

    Specifies the minimum required version for rule compatibility.
    """

    def action_type(self) -> ActionType:
        return ActionType.METADATA

    def init(self, rule_metadata: dict, data: str) -> None:
        """Store version requirement."""
        if not data:
            raise ValueError("Ver action requires version specification")
        self.required_version = data.strip()

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        """Version checking is metadata only."""
        pass
