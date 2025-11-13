"""SecRule parser for parsing ModSecurity rule syntax.

This module handles parsing of SecRule directives, including:
- Variables with modifiers (ARGS, REQUEST_HEADERS:User-Agent, &ARGS_NAMES)
- Operators with negation (@rx, !@within, @detectSQLi)
- Transformation chains (t:lowercase,t:removeWhitespace)
- Action lists with proper precedence
"""

from __future__ import annotations

import logging
import random
from typing import TYPE_CHECKING, Any

from lewaf.primitives.actions import ACTIONS
from lewaf.primitives.operators import OperatorOptions, get_operator
from lewaf.rules import Rule

if TYPE_CHECKING:
    from lewaf.seclang.parser import SecLangParser


class SecRuleParser:
    """Parser for SecRule directives.

    A SecRule has the format:
        SecRule VARIABLES OPERATOR [TRANSFORMATIONS] "ACTIONS"

    Example:
        SecRule REQUEST_HEADERS:User-Agent "@rx malicious" "id:1001,phase:1,deny"
    """

    def __init__(self, parser: SecLangParser):
        """Initialize the rule parser.

        Args:
            parser: Parent SecLang parser for context
        """
        self.parser = parser
        self.variables: list[tuple[str, str | None]] = []
        self.operator_name = ""
        self.operator_negated = False
        self.operator_argument = ""
        self.transformations: list[str] = []
        self.actions: dict[str, Any] = {}
        self.metadata: dict[str, int | str] = {}

    def parse_rule(self, rule_text: str) -> None:
        """Parse a complete SecRule directive.

        Args:
            rule_text: The rule text after "SecRule" keyword

        Format: VARIABLES OPERATOR [TRANSFORMATIONS] "ACTIONS"
        """
        # Use a simple state machine to parse the rule
        # We need to handle quoted strings carefully

        # Find the operator (starts with @ or is a quoted operator)
        # Variables come before operator
        # Actions are in quotes at the end

        parts = self._split_rule_parts(rule_text)

        if len(parts) < 3:
            msg = f"Invalid SecRule format: {rule_text[:100]}"
            raise ValueError(msg)

        variables_str = parts[0]
        operator_str = parts[1]
        actions_str = parts[2] if len(parts) >= 3 else ""

        # Parse each component
        self._parse_variables(variables_str)
        self._parse_operator(operator_str)
        self._parse_actions(actions_str)

        # Apply default actions for the phase
        self._apply_default_actions()

        # Create the Rule object
        self._create_rule()

    def _split_rule_parts(self, rule_text: str) -> list[str]:
        """Split rule text into: variables, operator, actions.

        This handles quoted strings properly.

        Args:
            rule_text: The complete rule text

        Returns:
            List of [variables, operator, actions]
        """
        parts = []
        current = []
        in_quotes = False
        escape_next = False

        for char in rule_text:
            if escape_next:
                current.append(char)
                escape_next = False
                continue

            if char == "\\":
                current.append(char)
                escape_next = True
                continue

            if char == '"':
                in_quotes = not in_quotes
                if not in_quotes and current:
                    # End of quoted section
                    parts.append("".join(current))
                    current = []
                continue

            if not in_quotes and char in (" ", "\t"):
                if current:
                    parts.append("".join(current))
                    current = []
                continue

            current.append(char)

        if current:
            parts.append("".join(current))

        return parts

    def _parse_variables(self, variables_str: str) -> None:
        """Parse variable specification.

        Formats:
        - ARGS - All arguments
        - REQUEST_HEADERS:User-Agent - Specific header
        - ARGS|REQUEST_COOKIES - Multiple variables
        - !ARGS:id - Negation
        - &ARGS_NAMES - Count

        Args:
            variables_str: Variable specification string
        """
        # Split by | to get individual variables
        var_parts = variables_str.split("|")

        for var_part in var_parts:
            var_part = var_part.strip()
            if not var_part:
                continue

            # Check for negation (!)
            is_negation = var_part.startswith("!")
            if is_negation:
                var_part = var_part[1:]

            # Check for count (&)
            is_count = var_part.startswith("&")
            if is_count:
                var_part = var_part[1:]
                # For now, we'll treat count as regular variable
                # TODO: Implement count handling

            # Split variable name and key
            if ":" in var_part:
                var_name, key = var_part.split(":", 1)
                key = key.strip()

                # Handle regex keys /pattern/
                if key.startswith("/") and key.endswith("/"):
                    key = key  # Keep as-is for now
                # Handle quoted keys
                elif key.startswith("'") and key.endswith("'"):
                    key = key[1:-1]
            else:
                var_name = var_part
                key = None

            # Normalize variable name
            var_name = var_name.strip().upper()

            # For negations, we'll need special handling
            # For now, add as regular variable
            # TODO: Implement proper negation handling
            self.variables.append((var_name, key))

    def _parse_operator(self, operator_str: str) -> None:
        """Parse operator specification.

        Formats:
        - @rx pattern - Regex operator
        - @within value - Within operator
        - !@eq 0 - Negated operator
        - @detectSQLi - No argument operator

        Args:
            operator_str: Operator specification string
        """
        operator_str = operator_str.strip()

        # Check for negation
        if operator_str.startswith("!"):
            self.operator_negated = True
            operator_str = operator_str[1:].strip()

        # Check for @ prefix
        if not operator_str.startswith("@"):
            # Some operators might not have @
            # Treat as unconditional or implicit operator
            self.operator_name = "rx"
            self.operator_argument = operator_str
            return

        # Remove @ prefix
        operator_str = operator_str[1:]

        # Split operator name and argument
        parts = operator_str.split(None, 1)
        self.operator_name = parts[0].lower()
        self.operator_argument = parts[1] if len(parts) > 1 else ""

        # Handle operators without arguments
        if not self.operator_argument and self.operator_name in [
            "unconditional",
            "unconditionalmatch",
            "detectsqli",
            "detectxss",
        ]:
            self.operator_argument = ""

    def _parse_actions(self, actions_str: str) -> None:
        """Parse action specification.

        Format: id:1001,phase:1,t:lowercase,t:trim,deny,status:403

        Args:
            actions_str: Comma-separated actions
        """
        if not actions_str:
            return

        # Split by comma, but handle escaped commas
        action_parts = self._split_actions(actions_str)

        for action_part in action_parts:
            action_part = action_part.strip()
            if not action_part:
                continue

            # Split action name and value
            if ":" in action_part:
                action_name, action_value = action_part.split(":", 1)
                action_name = action_name.strip().lower()
                action_value = action_value.strip()
            else:
                action_name = action_part.lower()
                action_value = ""

            # Handle transformation actions specially
            if action_name == "t":
                self.transformations.append(action_value.lower())
                continue

            # Handle metadata actions (id, phase, rev, severity, msg, etc.)
            if action_name in [
                "id",
                "phase",
                "rev",
                "severity",
                "ver",
                "maturity",
                "accuracy",
            ]:
                # Strip quotes from value
                if action_value.startswith("'") and action_value.endswith("'"):
                    action_value = action_value[1:-1]
                elif action_value.startswith('"') and action_value.endswith('"'):
                    action_value = action_value[1:-1]

                # Try to convert to int
                try:
                    if action_name in ["id", "phase", "severity"]:
                        self.metadata[action_name] = int(action_value)
                    else:
                        self.metadata[action_name] = action_value
                except ValueError:
                    self.metadata[action_name] = action_value
                continue

            # Handle other actions
            if action_name in ACTIONS:
                action_class = ACTIONS[action_name]
                action_instance = action_class()

                # Initialize action with value if needed
                if hasattr(action_instance, "init"):
                    try:
                        action_instance.init(self.metadata, action_value)
                    except Exception:
                        # Some actions don't need init
                        pass

                self.actions[action_name] = action_instance

    def _split_actions(self, actions_str: str) -> list[str]:
        """Split actions by comma, handling escaped commas.

        Args:
            actions_str: Comma-separated actions

        Returns:
            List of action strings
        """
        parts = []
        current = []
        escape_next = False

        for char in actions_str:
            if escape_next:
                current.append(char)
                escape_next = False
                continue

            if char == "\\":
                escape_next = True
                continue

            if char == ",":
                if current:
                    parts.append("".join(current))
                    current = []
                continue

            current.append(char)

        if current:
            parts.append("".join(current))

        return parts

    def _apply_default_actions(self) -> None:
        """Apply default actions for the rule's phase."""
        phase = self.metadata.get("phase", 2)

        # Get default actions for this phase
        # Cast phase to int for dict lookup (phase is always int in practice)
        phase_int = int(phase) if isinstance(phase, str) else phase
        default_actions_str = self.parser.default_actions.get(phase_int, "")

        if default_actions_str:
            # Parse default actions but don't override existing ones
            action_parts = default_actions_str.split(",")
            for action_part in action_parts:
                action_part = action_part.strip()
                if ":" in action_part:
                    action_name, _action_value = action_part.split(":", 1)
                    action_name = action_name.strip().lower()
                else:
                    action_name = action_part.lower()

                # Only apply if not already set
                if action_name not in self.actions and action_name in ACTIONS:
                    action_class = ACTIONS[action_name]
                    action_instance = action_class()
                    self.actions[action_name] = action_instance

    def _create_rule(self) -> None:
        """Create and register the Rule object with the WAF."""
        # Ensure we have required metadata
        if "id" not in self.metadata:
            # Generate a unique ID for rules without explicit IDs
            # This can happen with certain CRS rules (e.g., setvar-only rules)

            generated_id = random.randint(9000000, 9999999)
            self.metadata["id"] = generated_id

            logger = logging.getLogger(__name__)
            logger.debug("Generated ID %s for rule without explicit ID", generated_id)

        if "phase" not in self.metadata:
            self.metadata["phase"] = 2  # Default phase

        # Create the operator
        from lewaf.integration import ParsedOperator

        operator_options = OperatorOptions(self.operator_argument)
        operator_instance = get_operator(self.operator_name, operator_options)

        parsed_operator = ParsedOperator(
            name=self.operator_name,
            argument=self.operator_argument,
            negated=self.operator_negated,
            op=operator_instance,
        )

        # Collect tags from TagAction instances
        tags = []
        for action_name, action_instance in self.actions.items():
            if action_name == "tag" and hasattr(action_instance, "tag_name"):
                tags.append(action_instance.tag_name)

        # Create the Rule
        rule = Rule(
            variables=self.variables,
            operator=parsed_operator,
            transformations=self.transformations,
            actions=self.actions,
            metadata=self.metadata,
            tags=tags,
        )

        # Add to WAF
        self.parser.waf.rule_group.add(rule)

        # Log the rule creation
        logger = logging.getLogger(__name__)
        logger.info(
            f"Loaded rule {rule.id} (phase {rule.phase}) "
            f"with {len(self.variables)} variables, "
            f"operator '{self.operator_name}', "
            f"{len(self.transformations)} transformations, "
            f"{len(self.actions)} actions"
        )
