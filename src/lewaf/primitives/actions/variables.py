"""Variable management actions (setenv, setvar, deprecatevar, expirevar)."""

from __future__ import annotations

import logging
import os
import time

from ._base import (
    Action,
    ActionType,
    MacroExpander,
    RuleProtocol,
    TransactionProtocol,
    register_action,
)


@register_action("setenv")
class SetEnvAction(Action):
    """SetEnv action sets environment variables."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def init(self, rule_metadata: dict, data: str) -> None:
        """SetEnv action requires var=value format."""
        if not data or "=" not in data:
            msg = "SetEnv action requires var=value format"
            raise ValueError(msg)
        parts = data.split("=", 1)
        self.var_name = parts[0].strip()
        self.var_value = parts[1].strip()

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        logging.debug(f"Rule {rule.id} setting env {self.var_name}={self.var_value}")
        os.environ[self.var_name] = self.var_value


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
            msg = "SetVar action requires variable specification"
            raise ValueError(msg)
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

    def _get_collection(self, var_name: str, transaction: TransactionProtocol):
        """Get collection from variable name (e.g., 'tx.score' -> tx collection)."""
        if "." not in var_name:
            return None, None

        collection_name, var_key = var_name.split(".", 1)
        collection_attr = collection_name.lower()

        # Get collection from transaction.variables
        if hasattr(transaction.variables, collection_attr):
            return getattr(transaction.variables, collection_attr), var_key.lower()

        return None, None

    def _set_variable(
        self, var_name: str, value: str, transaction: TransactionProtocol
    ) -> None:
        """Set a variable in any collection (tx, ip, session, etc.)."""
        collection, var_key = self._get_collection(var_name, transaction)
        if collection:
            collection.remove(var_key)  # Clear existing
            collection.add(var_key, value)

    def _increment_variable(
        self, var_name: str, increment: str, transaction: TransactionProtocol
    ) -> None:
        """Increment a numeric variable in any collection."""
        collection, var_key = self._get_collection(var_name, transaction)
        if collection:
            current_values = collection.get(var_key)
            current_value = int(current_values[0]) if current_values else 0
            increment_value = int(increment) if increment.isdigit() else 0
            new_value = current_value + increment_value

            collection.remove(var_key)
            collection.add(var_key, str(new_value))

    def _decrement_variable(
        self, var_name: str, decrement: str, transaction: TransactionProtocol
    ) -> None:
        """Decrement a numeric variable in any collection."""
        collection, var_key = self._get_collection(var_name, transaction)
        if collection:
            current_values = collection.get(var_key)
            current_value = int(current_values[0]) if current_values else 0
            decrement_value = int(decrement) if decrement.isdigit() else 0
            new_value = current_value - decrement_value

            collection.remove(var_key)
            collection.add(var_key, str(new_value))

    def _delete_variable(self, var_name: str, transaction: TransactionProtocol) -> None:
        """Delete a variable from any collection."""
        collection, var_key = self._get_collection(var_name, transaction)
        if collection:
            collection.remove(var_key)


@register_action("deprecatevar")
class DeprecateVarAction(Action):
    """Mark a variable as deprecated with optional expiration time."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def init(self, rule_metadata: dict, data: str) -> None:
        """Parse deprecation specification."""
        if not data:
            msg = "DeprecateVar action requires variable specification"
            raise ValueError(msg)
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
            msg = "ExpireVar action requires var=seconds format"
            raise ValueError(msg)

        parts = data.split("=", 1)
        self.var_name = parts[0].strip()
        try:
            self.expire_seconds = int(parts[1].strip())
        except ValueError as e:
            msg = f"ExpireVar seconds must be integer: {parts[1]}"
            raise ValueError(msg) from e

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        # Store expiration info
        if not hasattr(transaction, "var_expiration"):
            transaction.var_expiration = {}

        expiry_timestamp = time.time() + self.expire_seconds
        transaction.var_expiration[self.var_name] = expiry_timestamp
