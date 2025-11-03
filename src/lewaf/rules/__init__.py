from __future__ import annotations

import logging

from typing import TYPE_CHECKING

from lewaf.primitives.collections import MapCollection, SingleValueCollection
from lewaf.primitives.transformations import TRANSFORMATIONS
from lewaf.primitives.actions import Action
from lewaf.transaction import Transaction
from typing import Any, Dict, List, Tuple, Union

if TYPE_CHECKING:
    from lewaf.integration import ParsedOperator


class Rule:
    def __init__(
        self,
        variables: List[Union[Tuple[str, None], Tuple[str, str]]],
        operator: ParsedOperator,
        transformations: List[Union[Any, str]],
        actions: Dict[str, Action],
        metadata: Dict[str, int],
    ):
        self.variables = variables
        self.operator = operator
        self.transformations = transformations
        self.actions = actions
        self.metadata = metadata
        self.id = metadata.get("id", 0)
        self.phase = metadata.get("phase", 1)

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

            match_result = self.operator.op.evaluate(transaction, transformed_value)
            # Handle negation
            if self.operator.negated:
                match_result = not match_result

            if match_result:
                logging.info(
                    "MATCH! Rule %s matched on value '%s'", self.id, transformed_value
                )
                for action in self.actions.values():
                    action.evaluate(self, transaction)
                return True
        return False
