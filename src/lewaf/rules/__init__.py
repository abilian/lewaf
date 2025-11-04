from __future__ import annotations

import logging
from dataclasses import dataclass, field as dataclass_field
from typing import TYPE_CHECKING, Any, cast

from lewaf.primitives.actions import Action, RuleProtocol, TransactionProtocol
from lewaf.primitives.collections import MapCollection, SingleValueCollection
from lewaf.primitives.transformations import TRANSFORMATIONS
from lewaf.transaction import Transaction

if TYPE_CHECKING:
    from lewaf.integration import ParsedOperator


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

        values_to_test = []
        for var_name, key in self.variables:
            collection = getattr(transaction.variables, var_name.lower())
            # TODO: use match operator
            if isinstance(collection, MapCollection):
                if key:
                    values_to_test.extend(collection.get(key))
                else:
                    values_to_test.extend(
                        match.value for match in collection.find_all()
                    )
            elif isinstance(collection, SingleValueCollection):
                values_to_test.append(collection.get())
            elif hasattr(collection, "find_all"):
                # Handle other collection types (FilesCollection, etc.)
                values_to_test.extend(match.value for match in collection.find_all())

        for value in values_to_test:
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
                cast(Any, transaction), transformed_value
            )
            # Handle negation
            if self.operator.negated:
                match_result = not match_result

            if match_result:
                logging.info(
                    "MATCH! Rule %s matched on value '%s'", self.id, transformed_value
                )
                for action in self.actions.values():
                    action.evaluate(
                        cast(RuleProtocol, self), cast(TransactionProtocol, transaction)
                    )
                return True
        return False
