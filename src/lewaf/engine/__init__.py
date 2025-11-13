from __future__ import annotations

import logging
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from lewaf.rules import Rule
    from lewaf.transaction import Transaction


class RuleGroup:
    def __init__(self):
        self.rules_by_phase = {1: [], 2: [], 3: [], 4: [], 5: []}

    def add(self, rule: Rule):
        phase = cast("int", rule.phase)  # Phase is always int in practice
        self.rules_by_phase[phase].append(rule)
        logging.debug("Added rule %s to phase %s", rule.id, phase)

    def evaluate(self, phase: int, transaction: Transaction):
        logging.info("--- Executing Phase %s ---", phase)
        rules = self.rules_by_phase[phase]

        i = 0
        while i < len(rules):
            rule = rules[i]

            # Check skip conditions
            if self._should_skip_rule(rule, transaction, i):
                i += 1
                continue

            # Handle chain processing
            if hasattr(transaction, "chain_state") and transaction.chain_state.get(
                "in_chain"
            ):
                # We're in a chain - this rule must match for chain to continue
                chain_result = self._evaluate_chain_rule(rule, transaction)
                if not chain_result:
                    # Chain broken - reset chain state and continue
                    self._reset_chain_state(transaction)
                i += 1
                continue

            # Normal rule evaluation
            rule_matched = rule.evaluate(transaction)

            # Handle post-rule processing
            self._handle_post_rule_processing(rule, rule_matched, transaction)

            if transaction.interruption:
                logging.warning(
                    "Transaction interrupted by rule %s. Halting phase.",
                    transaction.interruption["rule_id"],
                )
                return

            i += 1

    def _should_skip_rule(self, rule: Rule, transaction: Transaction, rule_index: int):
        """Check if a rule should be skipped based on skip actions."""
        if not hasattr(transaction, "skip_state"):
            return False

        skip_state = transaction.skip_state

        # Check skip_remaining
        if skip_state.get("skip_remaining"):
            return True

        # Check skip_next_count
        if skip_state.get("skip_next_count", 0) > 0:
            skip_state["skip_next_count"] -= 1
            return True

        # Check skip_after_id
        skip_after_id = skip_state.get("skip_after_id")
        if skip_after_id and rule.id == skip_after_id:
            # Found the target rule, start skipping after this one
            skip_state["skip_remaining"] = True
            return False  # Don't skip this rule, but skip all after it

        # Check skip_after_tag
        skip_after_tag = skip_state.get("skip_after_tag")
        if skip_after_tag:
            # If current rule has the target tag, clear skip state and don't skip this rule
            if hasattr(rule, "tags") and skip_after_tag in rule.tags:
                del skip_state["skip_after_tag"]
                return False  # Don't skip this rule, and stop skipping after it
            # Otherwise skip this rule (we haven't reached the target yet)
            return True

        return False

    def _evaluate_chain_rule(self, rule, transaction):
        """Evaluate a rule that's part of a chain."""
        rule_matched = rule.evaluate(transaction)

        if not rule_matched:
            # Chain broken
            logging.debug(f"Chain broken at rule {rule.id}")
            return False

        # Check if this rule has chain action (continues the chain)
        has_chain_action = any(
            action.__class__.__name__ == "ChainAction"
            for action in rule.actions.values()
        )

        if not has_chain_action:
            # End of chain - execute all chain actions
            logging.debug(f"End of chain at rule {rule.id}")
            self._execute_chain_actions(transaction)
            self._reset_chain_state(transaction)

        return True

    def _execute_chain_actions(self, transaction):
        """Execute actions for the completed chain."""
        # In a full implementation, this would execute the accumulated
        # actions from all rules in the chain
        logging.debug("Executing chain actions")

    def _reset_chain_state(self, transaction):
        """Reset chain processing state."""
        if hasattr(transaction, "chain_state"):
            transaction.chain_state.clear()

    def _handle_post_rule_processing(
        self, rule: Rule, rule_matched: bool, transaction: Transaction
    ):
        """Handle any post-rule processing like updating skip counts."""
        # Update skip counts if rule didn't match
        if not rule_matched and hasattr(transaction, "skip_state"):
            skip_state = transaction.skip_state
            if skip_state.get("skip_next_count", 0) > 0:
                skip_state["skip_next_count"] -= 1
