from __future__ import annotations

import logging
from dataclasses import dataclass, field as dataclass_field
from typing import TYPE_CHECKING, Any, cast

from lewaf.primitives.collections import MapCollection, SingleValueCollection
from lewaf.primitives.transformations import TRANSFORMATIONS

if TYPE_CHECKING:
    from lewaf.integration import ParsedOperator
    from lewaf.primitives.actions import Action, RuleProtocol, TransactionProtocol
    from lewaf.transaction import Transaction


@dataclass(frozen=True)
class Rule:
    """Immutable rule definition for WAF evaluation.

    Attributes:
        variables: List of (variable_name, key) tuples to extract values from transaction
        operator: Parsed operator to match against values
        transformations: List of transformation names to apply before matching
        actions: Dictionary of action name to Action instances
        metadata: Rule metadata including id and phase
        tags: List of tag strings for rule categorization and targeting
    """

    variables: list[tuple[str, str | None]]
    operator: ParsedOperator
    transformations: list[Any | str]
    actions: dict[str, Action]
    metadata: dict[str, int | str]
    tags: list[str] = dataclass_field(default_factory=list)

    @property
    def id(self) -> int | str:
        """Get rule ID from metadata."""
        return self.metadata.get("id", 0)

    @property
    def phase(self) -> int | str:
        """Get rule phase from metadata."""
        return self.metadata.get("phase", 1)

    def evaluate(self, transaction: Transaction):
        logging.debug(
            "Evaluating rule %s in phase %s...", self.id, transaction.current_phase
        )

        # Collect values with their full variable names for match tracking
        # Each item: (full_var_name, value) where full_var_name is like "ARGS:id"
        values_to_test: list[tuple[str, str]] = []
        for var_name, key in self.variables:
            collection = getattr(transaction.variables, var_name.lower())
            if isinstance(collection, MapCollection):
                if key:
                    for val in collection.get(key):
                        full_name = f"{var_name}:{key}"
                        values_to_test.append((full_name, val))
                else:
                    for match in collection.find_all():
                        full_name = f"{var_name}:{match.key}" if match.key else var_name
                        values_to_test.append((full_name, match.value))
            elif isinstance(collection, SingleValueCollection):
                values_to_test.append((var_name, collection.get()))
            elif hasattr(collection, "find_all"):
                # Handle other collection types (FilesCollection, etc.)
                for match in collection.find_all():
                    full_name = f"{var_name}:{match.key}" if match.key else var_name
                    values_to_test.append((full_name, match.value))

        for full_var_name, value in values_to_test:
            transformed_value = value
            for t_name in self.transformations:
                transformed_value, _ = TRANSFORMATIONS[t_name.lower()](
                    transformed_value
                )

            logging.debug(
                "Testing operator '%s' with arg '%s' against value '%s'",
                self.operator.name,
                self.operator.argument,
                transformed_value,
            )

            match_result = self.operator.op.evaluate(
                cast("Any", transaction), transformed_value
            )
            # Handle negation
            if self.operator.negated:
                match_result = not match_result

            if match_result:
                logging.info(
                    "MATCH! Rule %s matched on value '%s'", self.id, transformed_value
                )
                # Update MATCHED_VAR variables for CRS compatibility
                self._update_matched_vars(transaction, full_var_name, transformed_value)

                for action in self.actions.values():
                    action.evaluate(
                        cast("RuleProtocol", self),
                        cast("TransactionProtocol", transaction),
                    )
                return True
        return False

    def _update_matched_vars(
        self, transaction: Transaction, var_name: str, matched_value: str
    ) -> None:
        """Update MATCHED_VAR family of variables after a successful match.

        Args:
            transaction: The current transaction
            var_name: Full variable name (e.g., "ARGS:id")
            matched_value: The value that matched
        """
        # MATCHED_VAR: The value from the most recent match
        transaction.variables.matched_var.set(matched_value)

        # MATCHED_VAR_NAME: The name of the variable that matched
        transaction.variables.matched_var_name.set(var_name)

        # MATCHED_VARS: Collection of all matched values (keyed by index)
        # Use a counter to handle multiple matches
        counter = len(list(transaction.variables.matched_vars.find_all()))
        transaction.variables.matched_vars.add(str(counter), matched_value)

        # MATCHED_VARS_NAMES: Collection of all matched variable names
        transaction.variables.matched_vars_names.add(str(counter), var_name)
