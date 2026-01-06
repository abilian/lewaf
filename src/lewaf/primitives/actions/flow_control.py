"""Flow control actions (chain, skip, skipafter, skipnext, conditional, ctl)."""

from __future__ import annotations

import logging

from ._base import (
    Action,
    ActionType,
    RuleProtocol,
    TransactionProtocol,
    register_action,
)


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
    """Skip all rules after a specified rule ID, tag, or marker.

    This action causes rule processing to skip all rules that come after
    the specified rule ID, tag, or SecMarker within the current phase.

    This is commonly used in CRS for paranoia level filtering:
        SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" "skipAfter:END-SECTION"
        SecMarker "END-SECTION"
    """

    def action_type(self) -> ActionType:
        return ActionType.FLOW

    def init(self, rule_metadata: dict, data: str) -> None:
        """Initialize skipAfter with target.

        Args:
            rule_metadata: Rule metadata dict
            data: Rule ID, tag, or marker name
        """
        self.target = data.strip()

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        if not hasattr(transaction, "skip_state"):
            transaction.skip_state = {}

        # Support both self.target (new) and self.argument (old)
        target = getattr(self, "target", None) or getattr(self, "argument", None)

        if target:
            if target.isdigit():
                # Numeric rule ID
                transaction.skip_state["skip_after_id"] = int(target)
            else:
                # Marker name or tag - use skip_after_tag
                # SecMarker creates rules with tags, so this handles both cases
                transaction.skip_state["skip_after_tag"] = target
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


@register_action("skip")
class SkipAction(Action):
    """Skip action skips one or more rules."""

    def action_type(self) -> ActionType:
        return ActionType.FLOW

    def init(self, rule_metadata: dict, data: str) -> None:
        """Skip action requires number of rules to skip."""
        if not data:
            msg = "Skip action requires number of rules to skip"
            raise ValueError(msg)
        try:
            self.skip_count = int(data)
        except ValueError as e:
            msg = f"Skip count must be an integer: {data}"
            raise ValueError(msg) from e

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        logging.debug(f"Rule {rule.id} skipping {self.skip_count} rules")
        # Use skip_state mechanism for rule skipping
        if hasattr(transaction, "skip_state"):
            transaction.skip_state["skip_next_count"] = self.skip_count
        else:
            transaction.skip_rules_count = self.skip_count


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
            msg = "Conditional action requires condition,action format"
            raise ValueError(msg)

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

        if ">" in condition:
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
        if var_name.startswith("GEO."):
            geo_var = var_name[4:].lower()
            values = transaction.variables.geo.get(geo_var)
            return values[0] if values else ""
        if var_name.startswith("REMOTE_ADDR"):
            values = transaction.variables.remote_addr.get()
            return values[0] if values else ""
        if var_name == "MATCHED_VAR":
            return getattr(transaction, "matched_var", "")
        if var_name == "MATCHED_VAR_NAME":
            return getattr(transaction, "matched_var_name", "")
        # Add more variable types as needed
        return ""

    def _execute_conditional_actions(
        self, actions_str: str, rule: RuleProtocol, transaction: TransactionProtocol
    ) -> None:
        """Execute the conditional actions."""
        # This is a simplified implementation
        # In a full implementation, this would parse and execute actual actions

        logging.debug("Conditional actions triggered: %s", actions_str)


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
            msg = "Ctl action requires property=value format"
            raise ValueError(msg)

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
        # FIXME: is it safe to ignore invalid values here?
        try:  # noqa: SIM105
            transaction.body_limit = int(self.value)
        except ValueError:
            pass  # Invalid limit value
