"""Base classes and protocols for actions."""

from __future__ import annotations

import os
import re
import time
from enum import IntEnum
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable


class RuleProtocol(Protocol):
    """Protocol defining the minimal rule interface needed by actions."""

    id: int | str


class TransactionProtocol(Protocol):
    """Protocol defining the minimal transaction interface needed by actions."""

    # State attributes (may not exist initially, dynamically added)
    chain_state: dict[str, Any]
    skip_state: dict[str, Any]
    multimatch_state: dict[str, Any]
    deprecated_vars: set[str]
    var_expiration: dict[str, float]
    ctl_directives: dict[str, Any]
    collection_manager: Any  # PersistentCollectionManager (optional, added dynamically)

    # Engine control attributes
    rule_engine_enabled: bool
    rule_engine_mode: str
    body_processor: str
    body_limit: int

    # Audit logging control
    audit_log_enabled: bool
    force_audit_log: bool

    # Skip rules counter (for skip action)
    skip_rules_count: int

    # Variables (required)
    variables: Any  # TransactionVariables object

    def interrupt(
        self,
        rule: RuleProtocol,
        action: str = "deny",
        redirect_url: str | None = None,
    ) -> None:
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
        match var_spec:
            case "MATCHED_VAR":
                return getattr(transaction, "matched_var", "0")
            case "MATCHED_VAR_NAME":
                return getattr(transaction, "matched_var_name", "")
            case "TIME":
                return str(int(time.time() * 1000))  # Milliseconds
            case "TIME_SEC":
                return str(int(time.time()))  # Seconds
            case "UNIQUE_ID":
                return transaction.variables.unique_id.get()
            case "REQUEST_URI":
                return transaction.variables.request_uri.get()
            case "REQUEST_METHOD":
                return transaction.variables.request_method.get()
            case "REMOTE_ADDR":
                return transaction.variables.remote_addr.get()
            case "SERVER_NAME":
                return transaction.variables.server_name.get()
            case _:
                return ""

    @staticmethod
    def _resolve_collection_member(
        collection_name: str, member_key: str, transaction: TransactionProtocol
    ) -> str:
        """Resolve a collection member access."""
        collection_name = collection_name.upper()
        member_key = member_key.lower()

        # Handle different collection types
        match collection_name:
            case "TX":
                values = transaction.variables.tx.get(member_key)
            case "REQUEST_HEADERS":
                values = transaction.variables.request_headers.get(member_key)
            case "RESPONSE_HEADERS":
                values = transaction.variables.response_headers.get(member_key)
            case "ARGS":
                values = transaction.variables.args.get(member_key)
            case "REQUEST_COOKIES":
                values = transaction.variables.request_cookies.get(member_key)
            case "ENV":
                return os.environ.get(member_key.upper(), "")
            case "GEO":
                values = transaction.variables.geo.get(member_key)
            case _:
                return ""

        return values[0] if values else ""


# Global action registry
ACTIONS: dict[str, type[Action]] = {}


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
            msg = f"Unexpected arguments for {self.__class__.__name__}"
            raise ValueError(msg)

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        """Evaluate the action."""
        raise NotImplementedError

    def action_type(self) -> ActionType:
        """Return the type of this action."""
        raise NotImplementedError


def register_action(name: str) -> Callable:
    """Register an action by name."""

    def decorator(cls):
        ACTIONS[name.lower()] = cls
        return cls

    return decorator
