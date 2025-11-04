from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Union

from lewaf.engine import RuleGroup
from lewaf.primitives.actions import ACTIONS
from lewaf.primitives.operators import Operator, OperatorOptions, get_operator
from lewaf.rules import Rule
from lewaf.transaction import Transaction


@dataclass(frozen=True)
class ParsedOperator:
    """Container for parsed operator information."""

    name: str
    argument: str
    op: Operator
    negated: bool = False


@dataclass(frozen=True)
class SecLangParser:
    rule_group: RuleGroup

    def _normalize_line_continuations(self, rule_str: str) -> str:
        """Normalize line continuations by removing backslash-newline sequences."""
        import re

        # Remove backslash followed by optional whitespace and newline
        # This handles cases like "action,\" followed by newline and indentation
        # Be more careful to only remove actual line continuations, not escaped quotes
        normalized = re.sub(r"\\\s*\n\s*", "", rule_str)
        return normalized

    def _split_actions(self, actions_str: str) -> List[str]:
        """Split actions string on commas, but respect quoted values."""
        actions = []
        current_action = ""
        in_quotes = False
        quote_char = None

        for char in actions_str:
            if char in ("'", '"') and not in_quotes:
                in_quotes = True
                quote_char = char
                current_action += char
            elif char == quote_char and in_quotes:
                in_quotes = False
                quote_char = None
                current_action += char
            elif char == "," and not in_quotes:
                if current_action.strip():
                    actions.append(current_action.strip())
                current_action = ""
            else:
                current_action += char

        # Add the last action if any
        if current_action.strip():
            actions.append(current_action.strip())

        return actions

    def from_string(self, rule_str: str):
        # Preprocess line continuations: remove backslash-newline sequences
        normalized_rule = self._normalize_line_continuations(rule_str)

        parts = normalized_rule.split('"')
        if len(parts) < 5 or not parts[0].strip().startswith("SecRule"):
            raise ValueError(f"Invalid rule format: {rule_str}")

        variables_str = parts[0].replace("SecRule", "").strip()
        operator_str = parts[1]
        actions_str = parts[3]

        parsed_vars = []
        for var in variables_str.split("|"):
            if ":" in var:
                var_name, key = var.split(":", 1)
                parsed_vars.append((var_name.upper(), key))
            else:
                parsed_vars.append((var.upper(), None))

        # Handle negated operators like !@rx
        negated = False
        if operator_str.startswith("!"):
            negated = True
            operator_str = operator_str[1:]

        if operator_str.startswith("@"):
            parts = operator_str[1:].split(" ", 1)
            op_name = parts[0]
            op_arg = parts[1] if len(parts) > 1 else ""
        else:
            op_name, op_arg = "rx", operator_str

        try:
            options = OperatorOptions(op_arg)
            op_instance = get_operator(op_name, options)
            parsed_operator = ParsedOperator(op_name, op_arg, op_instance, negated)
        except ValueError as e:
            raise ValueError(f"Failed to create operator {op_name}: {e}") from e

        parsed_actions = {}
        parsed_transformations = []
        parsed_metadata = {}
        tags = []

        # Split actions properly, respecting quoted values
        actions = self._split_actions(actions_str)

        for action in actions:
            action = action.strip()
            key, _, value = action.partition(":")
            key = key.lower()

            if key == "t":
                parsed_transformations.append(value)
            else:
                action_class = ACTIONS.get(key)
                if not action_class:
                    raise ValueError(f"Unknown action: {key}")
                parsed_actions[key] = action_class(value)
                if key in ["id", "phase"]:
                    parsed_metadata[key] = int(value)
                if key == "tag":
                    tags.append(value)

        rule = Rule(
            parsed_vars,
            parsed_operator,
            parsed_transformations,
            parsed_actions,
            parsed_metadata,
            tags,
        )
        self.rule_group.add(rule)


class WAF:
    def __init__(self, config: Dict[str, Union[List[Any], List[str]]]):
        self.rule_group = RuleGroup()
        self.parser = SecLangParser(self.rule_group)
        for rule_str in config["rules"]:
            self.parser.from_string(rule_str)
        self._tx_counter = 0

    def new_transaction(self) -> Transaction:
        self._tx_counter += 1
        return Transaction(self, f"tx-{self._tx_counter}")
